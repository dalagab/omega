#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

p=argparse.ArgumentParser()
p.add_argument('report', type=Path)
p.add_argument('attestation', type=Path)
p.add_argument('--request', type=Path, help='optional omega.rift.execution-request.v1 JSON that v2 must bind')
a=p.parse_args()

report_bytes=a.report.read_bytes()
try:
    report=json.loads(report_bytes)
    att=json.loads(a.attestation.read_text(encoding='utf-8'))
except Exception as exc:
    raise SystemExit(f'invalid report/attestation JSON: {exc}')

if report.get('schema_version') != 'rift.runtime-observation.v2':
    raise SystemExit('attestation validation requires rift.runtime-observation.v2 report')
if att.get('schema_version') not in {'rift.supervisor-attestation.v1','rift.supervisor-attestation.v2'}:
    raise SystemExit(f"unexpected attestation schema: {att.get('schema_version')!r}")
if att.get('producer') != 'interdimensional-rift-supervisor':
    raise SystemExit('unexpected supervisor attestation producer')
if att.get('outcome') != 'runtime_report_emitted':
    raise SystemExit('unexpected supervisor attestation outcome')

hex64=re.compile(r'^[0-9a-f]{64}$')
for field in ('runtime_report_sha256','artifact_tree_sha256','entry_sha256'):
    value=att.get(field)
    if not isinstance(value,str) or not hex64.fullmatch(value):
        raise SystemExit(f'invalid supervisor attestation {field}')

actual_report_sha=hashlib.sha256(report_bytes).hexdigest()
if att.get('runtime_report_sha256') != actual_report_sha:
    raise SystemExit('runtime report hash does not match trusted supervisor attestation')

if att.get('schema_version') == 'rift.supervisor-attestation.v2':
    binding=att.get('omega_request')
    if not isinstance(binding,dict):
        raise SystemExit('v2 supervisor attestation missing omega_request binding')
    if not isinstance(binding.get('request_id'),str) or not binding['request_id']:
        raise SystemExit('invalid supervisor attestation omega_request.request_id')
    if not isinstance(binding.get('variant_id'),int) or isinstance(binding.get('variant_id'),bool) or binding['variant_id'] <= 0:
        raise SystemExit('invalid supervisor attestation omega_request.variant_id')
    if not isinstance(binding.get('artifact_sha256'),str) or not hex64.fullmatch(binding['artifact_sha256']):
        raise SystemExit('invalid supervisor attestation omega_request.artifact_sha256')
    if a.request is not None:
        request=json.loads(a.request.read_text(encoding='utf-8'))
        expected={
            'request_id': str(request.get('requestId') or ''),
            'variant_id': int(request.get('variantId') or 0),
            'artifact_sha256': str(request.get('artifactSha256') or '').lower(),
        }
        if binding != expected:
            raise SystemExit(f'Rift supervisor request binding mismatch: expected={expected!r} attested={binding!r}')
elif a.request is not None:
    raise SystemExit('a broker request requires rift.supervisor-attestation.v2')

if att.get('exercise_profile') not in {'post-init-safe-v1','none'}:
    raise SystemExit('invalid supervisor attestation exercise_profile')
framework_ticks=att.get('framework_ticks')
if not isinstance(framework_ticks,int) or isinstance(framework_ticks,bool) or not 0 <= framework_ticks <= 32:
    raise SystemExit('invalid supervisor attestation framework_ticks')
if att.get('network') != 'isolated' or att.get('seccomp') != 'enforced':
    raise SystemExit('supervisor attestation does not describe the required isolated/enforced boundary')
if not isinstance(att.get('wall_timeout_seconds'),int) or att['wall_timeout_seconds'] <= 0:
    raise SystemExit('invalid supervisor attestation wall_timeout_seconds')
if not isinstance(att.get('process_exit_code'),int) or isinstance(att.get('process_exit_code'),bool):
    raise SystemExit('invalid supervisor attestation process_exit_code')

execution=report.get('execution') or {}
checks=(
    ('artifact_tree_sha256', execution.get('artifact_tree_sha256'), att.get('artifact_tree_sha256')),
    ('artifact_tree_hash_algorithm', execution.get('artifact_tree_hash_algorithm'), att.get('artifact_tree_hash_algorithm')),
    ('entry_sha256', execution.get('entry_sha256'), att.get('entry_sha256')),
    ('exercise_profile', execution.get('exercise_profile'), att.get('exercise_profile')),
    ('framework_ticks', str(execution.get('framework_ticks')), str(att.get('framework_ticks'))),
    ('network', execution.get('network'), att.get('network')),
    ('seccomp', execution.get('seccomp'), att.get('seccomp')),
    ('boundary_profile', execution.get('boundary_profile'), att.get('boundary_profile')),
    ('contract_mode', execution.get('contract_mode'), att.get('contract_mode')),
    ('wall_timeout_seconds', str(execution.get('wall_timeout_seconds')), str(att.get('wall_timeout_seconds'))),
)
for name,left,right in checks:
    if left != right:
        raise SystemExit(f'attestation mismatch for {name}: report={left!r} supervisor={right!r}')

contract=att.get('dalamud_contract')
if not isinstance(contract,dict):
    raise SystemExit('supervisor attestation missing dalamud_contract')
for report_name,att_name in (
    ('dalamud_contract_track','track'),
    ('dalamud_contract_sha256','dalamud_sha256'),
    ('dalamud_contract_tree_sha256','tree_sha256'),
    ('dalamud_contract_hash_algorithm','hash_algorithm'),
):
    if execution.get(report_name) != contract.get(att_name):
        raise SystemExit(f'attestation mismatch for {report_name}')
for field in ('dalamud_sha256','tree_sha256'):
    value=contract.get(field)
    if not isinstance(value,str) or not hex64.fullmatch(value):
        raise SystemExit(f'invalid supervisor attestation dalamud_contract.{field}')

cgroup=att.get('cgroup')
if not isinstance(cgroup,dict):
    raise SystemExit('supervisor attestation missing cgroup')
cgroup_checks=(
    ('memory_max', execution.get('memory_max'), cgroup.get('memory_max')),
    ('memory_swap_max', execution.get('memory_swap_max'), cgroup.get('memory_swap_max')),
    ('tasks_max', str(execution.get('tasks_max')), str(cgroup.get('tasks_max'))),
    ('cpu_quota', execution.get('cpu_quota'), cgroup.get('cpu_quota')),
)
for name,left,right in cgroup_checks:
    if left != right:
        raise SystemExit(f'attestation mismatch for cgroup.{name}: report={left!r} supervisor={right!r}')
if cgroup.get('memory_swap_max') != '0':
    raise SystemExit('supervisor attestation does not preserve zero-swap policy')
for field in ('tasks_max','memory_oom_kill_delta','pids_max_delta'):
    value=cgroup.get(field)
    if not isinstance(value,int) or isinstance(value,bool) or value < (1 if field == 'tasks_max' else 0):
        raise SystemExit(f'invalid supervisor attestation cgroup.{field}')

tmpfs=att.get('tmpfs')
if not isinstance(tmpfs,dict):
    raise SystemExit('supervisor attestation missing tmpfs')
for report_name,att_name in (
    ('tmpfs_tmp_bytes','tmp_bytes'),
    ('tmpfs_home_bytes','home_bytes'),
    ('tmpfs_work_bytes','work_bytes'),
):
    if str(execution.get(report_name)) != str(tmpfs.get(att_name)):
        raise SystemExit(f'attestation mismatch for {report_name}')
    value=tmpfs.get(att_name)
    if not isinstance(value,int) or isinstance(value,bool) or value <= 0:
        raise SystemExit(f'invalid supervisor attestation tmpfs.{att_name}')

print(f"Rift supervisor attestation PASS: report_sha256={actual_report_sha}")
