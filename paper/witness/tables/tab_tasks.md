**Every AgentDojo task in which a security-relevant value is delegated to a tool output.**

| Suite | Task | Sink argument | Source | Attackable |
|---|---|---|---|---|
| banking | 15 | \texttt{send_money.recipient} | \texttt{get_most_recent_transactions} | yes |
| slack | 2 | \texttt{invite_user_to_slack.user_email} | \texttt{get_webpage} | yes |
| slack | 11 | \texttt{invite_user_to_slack.user_email} | \texttt{get_webpage} | yes |
| slack | 16 | \texttt{invite_user_to_slack.user_email} | \texttt{get_webpage} | yes |
| slack | 17 | \texttt{invite_user_to_slack.user_email} | \texttt{get_webpage} | yes |
| slack | 20 | \texttt{invite_user_to_slack.user_email} | \texttt{get_webpage} | yes |
| workspace | 9 | \texttt{create_calendar_event.participants} | \texttt{search_calendar_events} | yes |
| workspace | 21 | \texttt{create_calendar_event.participants} | \texttt{get_day_calendar_events} | yes |
| workspace | 18 | \texttt{create_calendar_event.participants} | \texttt{search_emails} | yes |
| workspace | 20 | \texttt{create_calendar_event.participants} | \texttt{search_contacts_by_name} | no |
| workspace | 33 | \texttt{send_email.recipients} | \texttt{search_files_by_filename} | yes |
| workspace | 25 | \texttt{send_email.recipients} | \texttt{search_files} | yes |

Found automatically by executing each task's ground truth with canary injections (experiments/find\_delegated\_tasks.py). Attackable = an injection slot lands in the same observation.
