# GitHub Organization Security & Access-Hygiene Automation



## Overview



GitHub Organization Security & Access-Hygiene Automation is a demonstration security automation project designed to assess GitHub repositories, security findings, member access, repository activity, contribution levels, and potential access-hygiene risks.



The project was built and tested in a controlled demonstration GitHub organization:



**Organization:** `manikanta-security-lab`



The objective is to automate the collection and analysis of GitHub security and access-related information and present the results through machine-readable reports and a security operations dashboard.



> **Important:** The automation never automatically removes GitHub access. Access removal is only recommended for human review.



---



# 1. Project Objectives



The automation addresses the following areas:



1\. Repository discovery

2\. Repository metadata collection

3\. GitHub Dependabot/security advisory analysis

4\. Repository member and permission analysis

5\. Repository activity analysis

6\. Commit contribution analysis

7\. Pull request analysis

8\. Pull request review analysis

9\. Contribution scoring

10\. Access-hygiene recommendations

11\. Security findings analysis

12\. Dashboard generation

13\. JSON and CSV reporting

14\. Repeatable execution



---



# 2. Demonstration Environment



A dedicated GitHub organization was created to demonstrate the automation.



### Organization



`manikanta-security-lab`



### Demonstration Repositories



| Repository | Purpose | Status |

|---|---|---|

| `security-demo-api` | Main API/security demonstration | Active |

| `security-demo-web` | Web application demonstration | Active |

| `security-demo-tools` | Security/tooling demonstration | Active |

| `security-demo-empty` | Empty repository edge-case test | Active |



Two GitHub accounts were used in the demonstration environment to demonstrate different repository access levels and contribution scenarios.



---



# 3. Project Structure

```text
github-security-automation/
│
├── automation/
│   └── github-security-scanner.ps1
│
├── analysis/
│   ├── analyze-security.ps1
│   └── analyze-contributions.ps1
│
├── dashboard/
│   └── index.html
│
├── data/
│   ├── repositories.json
│   ├── members.json
│   ├── advisories.json
│   ├── activity.json
│   ├── reviews.json
│   ├── security-test-findings.json
│   ├── contributions.json
│   └── access-recommendations.json
│
├── reports/
│   ├── security-report.json
│   └── security-report.csv
│
└── README.md
```

# 4. High-Level Architecture

The automation follows a staged workflow in which GitHub data collection is separated from contribution analysis and reporting.



&#x20;                   GitHub Organization

&#x20;                           |

&#x20;                           v

&#x20;                 Repository Discovery

&#x20;                           |

&#x20;             +-------------+-------------+

&#x20;             |                           |

&#x20;             v                           v

&#x20;      Repository Metadata        Security / Dependabot

&#x20;             |                           |

&#x20;             v                           v

&#x20;       Collaborators              Security Findings

&#x20;             |

&#x20;             v

&#x20;      Commit Activity

&#x20;             |

&#x20;             v

&#x20;      Pull Requests

&#x20;             |

&#x20;             v

&#x20;         PR Reviews

&#x20;             |

&#x20;             v

&#x20;    Contribution Analysis

&#x20;             |

&#x20;             v

&#x20;     Contribution Score

&#x20;             |

&#x20;             v

&#x20;   Access Recommendations

&#x20;             |

&#x20;             v

&#x20;      JSON / CSV Reports

&#x20;             |

&#x20;             v

&#x20;         Dashboard

Processing Flow

1\. Repository Discovery

Enumerates repositories in the GitHub organization.

Captures repository metadata such as visibility, default branch, archived status, fork status, and empty repository status.

Handles paginated API results.

2\. Security / Dependabot Collection

Collects available Dependabot security alerts.

Captures security finding information such as severity, package/dependency, state, and repository.

Security findings are stored as structured JSON data.

3\. Member & Access Collection

Enumerates repository collaborators.

Captures effective repository permission levels.

Identifies repository administrators so they can be excluded from access-removal recommendations.

4\. Contribution Collection

Collects commit activity within the configured lookback period.

Collects pull requests and their states.

Collects pull-request review events where available.

Records the most recent measurable activity.

# 5. Contribution Scoring Logic

The contribution score is calculated independently for each member on each repository.

Activity	Maximum Points

Commits authored	40

Pull requests opened	20

Pull requests merged	15

Reviews submitted	15

Recent activity	10

Maximum Score	100

Scoring Method



The implementation uses capped point allocation so that one activity type cannot dominate the entire score.

### Point Allocation

The demonstration implementation uses the following formulas:

- Commits: 2 points per authored commit, capped at 40 points.
- Pull requests opened: 5 points per opened pull request, capped at 20 points.
- Pull requests merged: 5 points per merged pull request, capped at 15 points.
- Reviews submitted: 5 points per submitted review, capped at 15 points.
- Recent activity:
  - 10 points when the latest measurable activity is within 30 days.
  - 7 points when the latest measurable activity is within 90 days.
  - 4 points when the latest measurable activity is within 180 days.
  - 0 points when there is no measurable recent activity or the activity is older than 180 days.

The final contribution score is the sum of these five components and is therefore limited to a maximum of 100 points.



Commits — 40 points



Commits authored during the configured 12-month lookback period contribute 2 points per commit, capped at 40 points.


Pull Requests Opened — 20 points



Members receive 5 points per pull request they opened during the configured lookback period, capped at 20 points.



Pull Requests Merged — 15 points



Members receive 5 points per successfully merged pull request during the configured lookback period, capped at 15 points.



Code Reviews — 15 points



Members receive 5 points per submitted pull-request review, capped at 15 points.



Recent Activity — 10 points



Recent activity provides an additional recency signal.



More recent activity receives more points, while members without measurable recent activity receive zero points.



Contribution Levels

Score	Level

80–100	High

50–79	Medium

1–49	Low

0	None



The score is intended as an access-hygiene signal, not as a performance rating.



A low score does not automatically mean access should be removed. It identifies an account that may require human review.



# 6. Access Recommendation Logic

The automation compares repository access with measured contribution activity.

Members with a contribution score of 20 or below are flagged for human review using:

`REVIEW_ACCESS`

The recommendation includes:

- Repository
- Member
- Current permission
- Contribution score
- Contribution level
- Supporting reason
- Automatic removal status

## Important Safety Control

Access removal is never automatically executed.

The automation only produces recommendations for a security administrator or repository owner to review.

Repository administrators are excluded from access-removal recommendations to avoid incorrectly flagging accounts that may have legitimate administrative responsibilities.

## Recommendation Threshold

The current demonstration policy uses:

| Condition | Action |
|---|---|
| Score 0 | `REVIEW_ACCESS` |
| Score 1–20 | `REVIEW_ACCESS` |
| Score 21+ | No access recommendation |
| Repository administrator | Excluded from recommendation |

The threshold is intentionally configurable and can be adjusted for a production access-review policy.

## Example

```text
Repository: security-demo-tools
Member: Mani27022
Permission: write
Contribution Score: 0
Contribution Level: None
Recommendation: REVIEW_ACCESS
Automatic Removal: false
```

# 7. Edge Cases Considered

Repository Administrators



Administrators are excluded from access-removal recommendations even when their measured contribution is low.



Administrative responsibilities may not require frequent commits or pull requests.



Brand-New Repositories



A newly created repository may have little or no historical activity.



Low contribution scores are therefore treated as an assessment signal rather than an automatic removal decision.



Empty Repositories



Empty repositories do not have commit history.



The scanner records the repository as empty and contribution activity can legitimately be zero.



Single-Contributor Repositories



A repository with only one active contributor is not automatically treated as an access-removal case.



The recommendation remains subject to human review.



Bots and Service Accounts



Automation accounts should not be treated like normal human contributors.



In a production implementation, bot/service-account identities should be classified separately and evaluated using ownership, workflow usage, and operational requirements.



Archived or Forked Repositories



Repository metadata records whether a repository is archived or a fork.



These attributes can be used to exclude or deprioritize repositories in a production access-review policy.



API Limitations



Some GitHub security information, particularly private security advisory data, may require additional repository or organization permissions.



Where live API access cannot provide required demonstration data, clearly identified test/mock data can be used rather than silently fabricating results.



# 8. Technology Stack

Technology	Purpose

GitHub REST API	Repository, collaborator, Dependabot, PR, commit and review data

PowerShell	Automation, data collection and analysis

JSON	Intermediate and machine-readable data storage

CSV	Human-readable report/export format

HTML	Dashboard interface

JavaScript	Dashboard logic and visualization

Chart.js	Dashboard charts

Git	Version control

GitHub	Source repository and demonstration organization



The implementation was intentionally kept lightweight so the complete workflow can be understood and demonstrated during a coding walkthrough.



# 9. Challenges Faced

GitHub API Data Availability



Different GitHub API endpoints expose different levels of information depending on repository visibility and token permissions.



Security advisory and Dependabot information can therefore require additional permissions.



Pagination



GitHub APIs return results in pages.



The scanner handles paginated API requests so the design can scale beyond the small demonstration organization.



Repository-Level Contribution Attribution



Repository-level commit activity and pull-request review data must be associated with individual members carefully.



The analysis avoids assigning repository-level activity to every collaborator.



Empty Repository Handling



An empty repository has no commit history.



The scanner handles this condition without causing the complete scan to fail.



Access Safety



The task requires access removal to remain recommendation-only.



The implementation therefore produces access-review recommendations instead of calling GitHub access-removal endpoints.



Dashboard Data Loading



The dashboard reads generated report data separately from the collection and analysis scripts.



This keeps visualization independent from the GitHub API collection process.



# 10. AI / LLM Usage



AI assistance was used during development as a development-support tool.



It was used for:



Structuring the automation workflow.

Reviewing PowerShell logic.

Identifying edge cases in GitHub API processing.

Improving the contribution-scoring approach.

Assisting with dashboard structure and presentation.

Troubleshooting implementation issues.

Improving documentation and explaining design decisions.



AI-generated suggestions were not treated as authoritative.



GitHub API behavior, generated output, PowerShell execution results, repository data, contribution calculations, and dashboard behavior were manually verified during testing.



Where AI suggestions did not match the actual project output, the implementation was adjusted based on real execution results.



# 11. Production-Readiness Improvements


For a production deployment, the following improvements would be considered:



Store GitHub credentials in a secure secrets manager.

Use GitHub App authentication instead of long-lived personal access tokens where appropriate.

Implement stronger API rate-limit handling and exponential backoff.

Add persistent storage for historical scans.

Track changes between scans instead of only producing point-in-time results.

Add organization-level team membership analysis.

Distinguish human users, bots, service accounts and automation identities.

Improve security-advisory coverage using organization-level security APIs where permitted.

Add automated unit and integration tests.

Add structured logging and error reporting.

Run the workflow through a scheduled automation platform such as n8n.

Add authentication to the dashboard.

Add historical contribution and access-risk trends.

Support large organizations with parallelized but rate-limit-aware API collection.

# 12. Running the Automation

Prerequisites

Windows PowerShell

Git

GitHub account

GitHub organization

GitHub Personal Access Token with appropriate permissions



Set the GitHub token before running the scanner:



$env:GITHUB_TOKEN = "YOUR_GITHUB_TOKEN"



Never commit the GitHub token to the repository.



Step 1 — Run the GitHub Scanner



From the project root:



.\\automation\\github-security-scanner.ps1



The scanner collects repository, collaborator, security, activity, pull-request and review data.



Generated data is stored under:



data/

Step 2 — Run Security Analysis

.\\analysis\\analyze-security.ps1



This processes security findings and generates the security report.



Step 3 — Run Contribution Analysis

.\\analysis\\analyze-contributions.ps1



This calculates contribution scores and produces access recommendations.



Generated files:



data/contributions.json

data/access-recommendations.json

Step 4 — View the Dashboard



The dashboard is located at:



dashboard/index.html



Because the dashboard loads JSON data, it should be served through a local HTTP server rather than opened directly with file://.



For example:



python -m http.server 8000



Then open:



http://localhost:8000/dashboard/

# 13. Output Files

Repository Data

data/repositories.json



Contains repository metadata including:



Repository name

Visibility

Archived status

Fork status

Default branch

Empty repository status

Member Data

data/members.json



Contains repository collaborators and permission information.



Security Data

data/advisories.json

data/security-test-findings.json



Contains available security/advisory information and controlled demonstration findings where required.



Activity Data

data/activity.json



Contains repository activity and recent commit information.



Review Data

data/reviews.json



Contains pull-request and review information.



Contribution Results

data/contributions.json



Contains per-repository contribution scores.



Access Recommendations

data/access-recommendations.json



Contains recommendation-only access-hygiene findings.



Security Reports

reports/security-report.json

reports/security-report.csv



These files provide machine-readable and human-readable security reporting outputs.



# 14. Dashboard


The project includes a security operations dashboard designed for a security lead to quickly understand the current assessment.



The dashboard provides:



Critical findings

High findings

Medium findings

Low findings

Total findings

Severity distribution

Findings by type

Repository risk overview

Critical and high-priority findings

Detailed security findings table



The dashboard is intentionally designed to provide a quick security overview while keeping detailed findings available for investigation.



# 15. Demonstration Results


The demonstration organization contains four repositories and two accounts with different repository permissions.



The contribution analysis generated:



Repositories analyzed : 4

Members/access records : 8

Contribution records   : 8

Access recommendations: 4



The demonstration also includes an empty repository to validate an important edge case.



Example access recommendations include members with:



Low contribution



or:



No measurable contribution



These are reported as:



REVIEW_ACCESS



and are not automatically removed.



Repository administrators are excluded from these recommendations.

# 16. Testing and Validation

The project was tested using both real GitHub demonstration data and controlled security test findings.

The testing focused on validating the complete workflow from data collection through analysis, recommendation generation, reporting, and dashboard presentation.

### GitHub Scanner Validation

The GitHub scanner was executed successfully against the demonstration organization.

The scanner successfully collected repository, member, activity, pull-request, review, and available security-related information.

The demonstration environment contains four repositories:

- `security-demo-api`
- `security-demo-web`
- `security-demo-tools`
- `security-demo-empty`

The empty repository was included specifically to validate handling of repositories without commit history.

### Contribution Analysis Validation

The contribution analysis script was executed successfully.

The observed execution results were:

Members loaded       : 8
Activity records     : 4
Review records       : 2
Repositories loaded  : 4

Contribution records     : 8
Access recommendations   : 4

The generated contribution output was inspected to verify that:

- repository administrators were excluded from access recommendations;
- low-contribution members could be flagged for human review;
- members with no measurable contribution activity received a score of 0;
- contribution scores were calculated using the documented scoring model;
- access recommendations remained recommendation-only.

### Access Recommendation Validation

The analysis generated four `REVIEW_ACCESS` recommendations for the demonstration member with low or no measurable contribution activity.

The generated recommendations contained:

- repository
- member
- current permission
- contribution score
- contribution level
- recommendation
- supporting reason
- automatic removal status

The generated output confirmed:

Recommendation: REVIEW_ACCESS
AutomaticRemoval: false

This validates that the automation identifies potential access-hygiene cases without automatically removing repository access.

### Edge-Case Validation

The demonstration environment included an empty repository.

The analysis completed successfully for the empty repository and produced zero contribution activity without causing the overall analysis to fail.

The project also validated the administrator exclusion rule. Repository administrators with low measured contribution activity were not included in the access-removal recommendation output.

### Dashboard Validation

The dashboard was validated against the generated JSON data.

The dashboard loads:

- repository data
- member data
- security reports
- contribution results
- access recommendations
- advisory data

The dashboard was tested using a local HTTP server because the implementation loads JSON files using `fetch()`.

### Overall Validation Result

The complete demonstration workflow executed successfully:

GitHub Scanner
      ↓
JSON Data Collection
      ↓
Security Analysis
      ↓
Contribution Analysis
      ↓
Access Recommendations
      ↓
Dashboard

The validation confirmed that the project can collect GitHub data, analyze security and contribution information, generate recommendation-only access-hygiene findings, and present the results through the dashboard.

# 17. Security and Safety Considerations



The project follows a recommendation-only approach for access hygiene.



It does not:



Remove users automatically

Change repository permissions automatically

Delete repositories

Modify GitHub security settings automatically



The system only collects information, calculates risk/contribution signals, and produces recommendations for human review.



GitHub credentials are supplied through the environment and should never be committed to source control.



# 18. Scope and Limitations



This project is a demonstration implementation rather than a production GitHub security platform.



The demonstration organization is intentionally small.



Some GitHub security and organization-level information may require additional GitHub permissions or APIs that are not available in every environment.



Where an API limitation prevents practical demonstration, controlled test data is used and clearly identified.



The production version would add stronger authentication, persistent storage, historical analysis, centralized logging, more comprehensive organization/team analysis, and stronger rate-limit handling.



## 19. Conclusion

GitHub Organization Security & Access-Hygiene Automation demonstrates an end-to-end approach for assessing GitHub repository security and access hygiene.

The project combines:

GitHub API
    ↓
Repository & Security Collection
    ↓
Member & Activity Analysis
    ↓
Contribution Scoring
    ↓
Access-Hygiene Recommendations
    ↓
Security Reports
    ↓
Dashboard

The solution provides security teams with a repeatable way to identify security findings, understand repository access, measure contribution activity, and highlight accounts that may require access review.

The final decision to remove or retain access remains with a human administrator.
