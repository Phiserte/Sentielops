#!/usr/bin/env python3
"""
Test script to run SecurityAgent against the test repository.
"""

import asyncio
from pathlib import Path

from app.agents.security.security_agent import SecurityAgent


async def main():
    repo_path = Path("test_automation")
    
    print(f"Scanning repository: {repo_path.absolute()}")
    print("=" * 60)
    
    # Create SecurityAgent with LLM analysis enabled
    agent = SecurityAgent(enable_llm_analysis=True)
    # Limit contexts for testing
    agent._context_selector = agent._context_selector.__class__(
        max_total_context_chars=10000
    )
    
    # Run the scan
    result = await agent.scan_async(repo_path)
    
    print(f"\nScan completed in {result.scan_duration_ms:.2f}ms")
    print(f"Files scanned: {result.files_scanned}")
    print(f"Total findings: {len(result.findings)}")
    print(f"  Heuristic findings: {len(result.heuristic_findings)}")
    print(f"  SAST findings: {len(result.sast_findings)}")
    print(f"Risk level: {result.risk_level}")
    print()
    
    # Print heuristic findings
    print("HEURISTIC FINDINGS:")
    print("-" * 60)
    for finding in result.heuristic_findings:
        print(f"  [{finding.severity.value}] {finding.rule_id}: {finding.message}")
        print(f"    File: {finding.file}:{finding.line}")
        print(f"    Evidence: {finding.evidence}")
        print()
    
    # Print SAST findings
    print("SAST FINDINGS (Bandit):")
    print("-" * 60)
    for finding in result.sast_findings:
        print(f"  [{finding.severity.value}] {finding.rule_id}: {finding.message}")
        print(f"    File: {finding.file}:{finding.line}")
        print(f"    Evidence: {finding.evidence}")
        print()
    
    # Print context selections
    print(f"CONTEXT SELECTIONS: {len(result.finding_contexts)}")
    print("-" * 60)
    for ctx in result.finding_contexts:
        print(f"  {ctx.finding.rule_id} -> {ctx.context.file_path}:{ctx.context.start_line}-{ctx.context.end_line}")
    
    # Print LLM analysis
    if result.llm_analysis:
        print("\nLLM ANALYSIS:")
        print("-" * 60)
        print(f"Summary: {result.llm_analysis.summary}")
        print(f"Risk Level: {result.llm_analysis.risk_level}")
        print(f"Recommendations: {result.llm_analysis.recommendations}")
        print(f"Errors: {result.llm_analysis.errors}")
        print()
        
        print("LLM VALIDATED FINDINGS:")
        for finding in result.llm_analysis.findings:
            print(f"  [{finding.severity}] {finding.rule_id} - Valid: {finding.is_valid}, FP: {finding.is_false_positive}")
            print(f"    File: {finding.file}:{finding.line}")
            print(f"    Message: {finding.message}")
            print(f"    Explanation: {finding.explanation}")
            print(f"    Attack Scenario: {finding.attack_scenario}")
            print(f"    Remediation: {finding.remediation}")
            if finding.additional_issues:
                print(f"    Additional Issues: {finding.additional_issues}")
            print()
        
        if result.llm_analysis.raw_response:
            print(f"Raw LLM Response Length: {len(result.llm_analysis.raw_response)} chars")
    else:
        print("\nLLM ANALYSIS: Not run (no findings or disabled)")
    
    # Summary by file
    print("\nSUMMARY BY FILE:")
    print("-" * 60)
    from collections import defaultdict
    file_findings = defaultdict(list)
    for f in result.findings:
        file_findings[f.file].append(f)
    
    for file, findings in file_findings.items():
        print(f"\n  {file}: {len(findings)} findings")
        for f in findings:
            src = "HEURISTIC" if f in result.heuristic_findings else "SAST"
            print(f"    [{f.severity.value}] {f.rule_id} ({src}) - Line {f.line}: {f.message[:80]}")


if __name__ == "__main__":
    asyncio.run(main())