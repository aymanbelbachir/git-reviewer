"""Assemble and run the review graph (docs/SPEC.md "LangGraph graph"; ARCHITECTURE.md §5).

collect diff -> static analysis -> anti-injection guardian (before) -> LLM review -> anti-injection
guardian (after) -> [with --run-tests: execution guardian (before) -> sandbox tests -> execution
guardian (after)] -> [with --fix: up to 3 rounds of propose patch -> check -> validate in the
sandbox -> patch auditor] -> final report. Any block goes straight to the final report.
"""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, START, StateGraph

from git_reviewer.report.model import Report

from . import fix, nodes
from .state import ReviewContext, ReviewState

RECURSION_LIMIT = 60


def build_graph() -> Any:
    graph = StateGraph(ReviewState, context_schema=ReviewContext)
    graph.add_node("collect_diff", nodes.collect_diff)
    graph.add_node("static_analysis", nodes.static_analysis)
    graph.add_node("injection_guard_pre", nodes.injection_guard_pre)
    graph.add_node("llm_review", nodes.llm_review)
    graph.add_node("injection_guard_post", nodes.injection_guard_post)
    graph.add_node("execution_guard_pre", nodes.execution_guard_pre)
    graph.add_node("sandbox_tests", nodes.sandbox_tests)
    graph.add_node("execution_guard_post", nodes.execution_guard_post)
    graph.add_node("prepare_fix", fix.prepare_fix)
    graph.add_node("propose_patch", fix.propose_patch)
    graph.add_node("check_patch", fix.check_patch)
    graph.add_node("validate_patch", fix.validate_patch)
    graph.add_node("audit_patch", fix.audit_patch)
    graph.add_node("final_report", nodes.final_report)
    graph.add_edge(START, "collect_diff")
    graph.add_conditional_edges("collect_diff", nodes.route_after_collect)
    graph.add_edge("static_analysis", "injection_guard_pre")
    graph.add_conditional_edges("injection_guard_pre", nodes.route_after_pre)
    graph.add_conditional_edges("llm_review", nodes.route_after_review)
    graph.add_conditional_edges("injection_guard_post", nodes.route_after_post)
    graph.add_conditional_edges("execution_guard_pre", nodes.route_after_execution_pre)
    # Once anything may have run, the after-run checks always follow.
    graph.add_edge("sandbox_tests", "execution_guard_post")
    graph.add_conditional_edges("execution_guard_post", nodes.route_after_execution_post)
    graph.add_conditional_edges("prepare_fix", fix.route_after_prepare)
    graph.add_conditional_edges("propose_patch", fix.route_after_propose)
    graph.add_conditional_edges("check_patch", fix.route_after_check)
    graph.add_conditional_edges("validate_patch", fix.route_after_validate)
    graph.add_conditional_edges("audit_patch", fix.route_after_audit)
    graph.add_edge("final_report", END)
    # No checkpointer: nothing from the review is persisted.
    return graph.compile()


def run_review(context: ReviewContext) -> Report:
    initial = {
        "decisions": (),
        "run_tests": context.sandbox is not None,
        "fix": context.fix and context.sandbox is not None,
    }
    state = build_graph().invoke(
        initial, config={"recursion_limit": RECURSION_LIMIT}, context=context
    )
    report = state["report"]
    if not isinstance(report, Report):
        raise RuntimeError("the review graph did not produce a report")
    return report
