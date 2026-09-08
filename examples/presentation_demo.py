from pathlib import Path
import json,sys
from capsule.profile import load_profile_file
from capsule.interpose import Interposer,CapabilityViolation
from capsule.hosts.claude_code import ClaudeCodeAdapter
from capsule.trap import TrapLog
profile_name=sys.argv[1] if len(sys.argv)>1 else "network-deny"
profile=load_profile_file(f"examples/profiles/{profile_name}.yaml",base_dir=Path.cwd())
log=TrapLog.in_memory();executed=[]
def simulated_host(tool,data):executed.append(tool);return "callback ran"
guarded=ClaudeCodeAdapter(Interposer(profile,trap_log=log,emit=lambda line:None)).guard_tool_use(simulated_host)
rows=[]
for tool,data in [("Read",{"file_path":"./examples/presentation_demo.py"}),("Write",{"file_path":"./forbidden.txt"}),("WebFetch",{"url":"https://example.invalid/fixture"})]:
 try:guarded(tool,data);rows.append({"tool":tool,"decision":"allow"})
 except CapabilityViolation as exc:rows.append({"tool":tool,"decision":"deny","rule":exc.decision.rule})
print(json.dumps({"profile":profile_name,"decisions":rows,"callbacks_executed":executed,"summary":log.summary()},indent=2))
