# Cases menu - a unified way to handle vulnerabilites, alarms,findings, software, hosts and more.

The case panel should be the place where all investigations happen. Where the users are adding notes, deciding on decisions and so on. 
Everything that is in the platform should be able to be added to the cases. For example there is something happening on a host with SSH. Then the user want to add the host, SSH, the SSH alarm etc to the case and be able to view all the corresponding information in one place. CASES DO NOT REPLACE the other views.

## Remove triage from alarms and findings, or sit on top?
Phase #1 ship cases alongside the already existing triage, and keep alarm and finding triage as it. This feature will eventually replace the already existing triage. 

Phase #2 make sure the user are to add already existing vulnerabilites, alarms and findings to a case. 

## Statuses
* open
* under investigation
* mitigated
* false positive
* accepted risk
* closed

## be able to assign other yourself or others into a case.
- Based on the roles. 

## What does closing a case do to its items?
- Depends on what kind of finding it is. if it is a vulnerability the user could mark it as false positive, but a vulnerability can really only get removed if the vulnerability isn't found anymore.
- Alarm, they should be able to close the alarm. Unless it keeps happening. Supress is still possible
- Findings, same thing. 
- TLDR Nothing should really be "deleted" or closed unless there actually are evidence that it is closed. A user might accept the risk of still having, but then things should be marked as.

## Can an item be in more than one case? 
- No and yes
- A specific finding should never be able to be in two cases at the same time to allow unessary work between analysts. But things like hosts, software and so on that can exists on multiple hosts can be in the same cases. 
- Vulnerabilites can also be in multiple cases but, a vulnerabilty and the same host togheter can not be in the same case as another case. Thats when it becomes to specific.