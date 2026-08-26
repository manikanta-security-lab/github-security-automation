# GitHub Security & Access Automation
# Demonstration scanner for manikanta-security-lab

$ErrorActionPreference = "Stop"

# -----------------------------
# Configuration
# -----------------------------

$Org = "manikanta-security-lab"
$LookbackMonths = 12

$Headers = @{
    Authorization          = "Bearer $env:GITHUB_TOKEN"
    Accept                 = "application/vnd.github+json"
    "X-GitHub-Api-Version" = "2022-11-28"
}

# -----------------------------
# Helper: GitHub API request
# -----------------------------

function Invoke-GitHubApi {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Uri
    )

    Write-Host "GET $Uri"

    return Invoke-RestMethod `
        -Uri $Uri `
        -Headers $Headers `
        -Method Get
}

# -----------------------------
# Get all organization repos
# -----------------------------

function Get-AllOrgRepositories {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Org
    )

    $allRepos = @()
    $page = 1

    while ($true) {

        Write-Host "Fetching repository page $page..."

        $uri = "https://api.github.com/orgs/$Org/repos?per_page=100&page=$page"

        $repos = Invoke-GitHubApi -Uri $uri

        if ($null -eq $repos -or $repos.Count -eq 0) {
            break
        }

        $allRepos += $repos
        $page++
    }

    return $allRepos
}

# -----------------------------
# Get repository collaborators
# -----------------------------

function Get-RepositoryCollaborators {
    param (
        [string]$Org,
        [string]$Repo
    )

    $uri = "https://api.github.com/repos/$Org/$Repo/collaborators?per_page=100"

    return Invoke-GitHubApi -Uri $uri
}

# -----------------------------
# Get Dependabot alerts
# -----------------------------

function Get-DependabotAlerts {
    param (
        [string]$Org,
        [string]$Repo
    )

    $uri = "https://api.github.com/repos/$Org/$Repo/dependabot/alerts?per_page=100"

    return Invoke-GitHubApi -Uri $uri
}

# -----------------------------
# Get commits
# -----------------------------

function Get-RepositoryCommits {
    param (
        [string]$Org,
        [string]$Repo,
        [string]$Since
    )

    $encodedSince = [System.Uri]::EscapeDataString($Since)

    $uri = "https://api.github.com/repos/$Org/$Repo/commits?since=$encodedSince&per_page=100"

    return Invoke-GitHubApi -Uri $uri
}

# -----------------------------
# Get pull requests
# -----------------------------

function Get-RepositoryPullRequests {
    param (
        [string]$Org,
        [string]$Repo
    )

    $uri = "https://api.github.com/repos/$Org/$Repo/pulls?state=all&per_page=100"

    return Invoke-GitHubApi -Uri $uri
}

# -----------------------------
# Get PR reviews
# -----------------------------

function Get-PullRequestReviews {
    param (
        [string]$Org,
        [string]$Repo,
        [int]$PullRequestNumber
    )

    $uri = "https://api.github.com/repos/$Org/$Repo/pulls/$PullRequestNumber/reviews?per_page=100"

    return Invoke-GitHubApi -Uri $uri
}

# -----------------------------
# Main scan
# -----------------------------

Write-Host ""
Write-Host "============================================="
Write-Host " GitHub Security & Access Scanner"
Write-Host " Organization: $Org"
Write-Host "============================================="
Write-Host ""

$since = (Get-Date).ToUniversalTime().
    AddMonths(-$LookbackMonths).
    ToString("yyyy-MM-ddTHH:mm:ssZ")

Write-Host "Lookback period: $since"
Write-Host ""

# -----------------------------
# Get repositories
# -----------------------------

$repositories = Get-AllOrgRepositories -Org $Org

Write-Host ""
Write-Host "Total repositories found: $($repositories.Count)"
Write-Host ""

# -----------------------------
# Results containers
# -----------------------------

$repositoryResults = @()
$memberResults     = @()
$advisoryResults   = @()
$activityResults   = @()
$reviewResults     = @()

# -----------------------------
# Process each repository
# -----------------------------

foreach ($repo in $repositories) {

    Write-Host ""
    Write-Host "---------------------------------------------"
    Write-Host "Processing repository: $($repo.name)"
    Write-Host "---------------------------------------------"

    $repoName = $repo.name

    # ------------------------------------------
    # Collaborators
    # ------------------------------------------

    $collaborators = Get-RepositoryCollaborators `
        -Org $Org `
        -Repo $repoName

    foreach ($collaborator in $collaborators) {

        $memberResults += [PSCustomObject]@{
            Repository = $repoName
            Login      = $collaborator.login
            Admin      = $collaborator.permissions.admin
            Maintain   = $collaborator.permissions.maintain
            Push       = $collaborator.permissions.push
            Triage     = $collaborator.permissions.triage
            Pull       = $collaborator.permissions.pull
        }
    }

    # ------------------------------------------
    # Dependabot
    # ------------------------------------------

    $alerts = Get-DependabotAlerts `
        -Org $Org `
        -Repo $repoName

    if ($null -ne $alerts) {

        foreach ($alert in $alerts) {

            $created = $alert.created_at

            $ageDays = if ($created) {
                (
                    (Get-Date).ToUniversalTime() -
                    [DateTime]$created
                ).Days
            }
            else {
                $null
            }

            $advisoryResults += [PSCustomObject]@{
                Repository = $repoName
                Severity   = $alert.security_advisory.severity
                Package    = $alert.dependency.package.name
                State      = $alert.state
                CreatedAt  = $alert.created_at
                AgeDays    = $ageDays
            }
        }
    }

    # ------------------------------------------
    # Commits
    # ------------------------------------------

    $isEmpty = $false
    $commits = @()

    try {

        $commits = Get-RepositoryCommits `
            -Org $Org `
            -Repo $repoName `
            -Since $since

        Write-Host "Commits found: $($commits.Count)"

        if ($commits.Count -gt 0) {

            $latestCommit = $commits[0]

            $activityResults += [PSCustomObject]@{
                Repository      = $repoName
                CommitCount     = $commits.Count
                LatestCommitAt  = $latestCommit.commit.author.date
                LatestCommitter = $latestCommit.author.login
            }
        }
        else {

            $activityResults += [PSCustomObject]@{
                Repository      = $repoName
                CommitCount     = 0
                LatestCommitAt  = $null
                LatestCommitter = $null
            }
        }
    }
    catch {

        if ($_.Exception.Response.StatusCode.value__ -eq 409) {

            Write-Host "Repository is empty - skipping commit analysis."

            $isEmpty = $true
            $commits = @()

            $activityResults += [PSCustomObject]@{
                Repository      = $repoName
                CommitCount     = 0
                LatestCommitAt  = $null
                LatestCommitter = $null
            }
        }
        else {

            throw
        }
    }

    # ------------------------------------------
    # Save repository metadata
    # ------------------------------------------

    $repositoryResults += [PSCustomObject]@{
        Repository    = $repoName
        Private       = $repo.private
        Archived      = $repo.archived
        Fork          = $repo.fork
        DefaultBranch = $repo.default_branch
        Empty         = $isEmpty
    }

    # ------------------------------------------
    # Pull requests
    # ------------------------------------------

    $pullRequests = Get-RepositoryPullRequests `
        -Org $Org `
        -Repo $repoName

    Write-Host "Pull requests found: $($pullRequests.Count)"

# ------------------------------------------
# Reviews
# ------------------------------------------

foreach ($pr in $pullRequests) {

    $reviews = Get-PullRequestReviews `
        -Org $Org `
        -Repo $repoName `
        -PullRequestNumber $pr.number

    Write-Host "PR #$($pr.number): $($reviews.Count) reviews"

    # --------------------------------------
    # No reviews
    # --------------------------------------

    if ($null -eq $reviews -or $reviews.Count -eq 0) {

        $reviewResults += [PSCustomObject]@{
            Repository        = $repoName
            PullRequest       = $pr.number
            PullRequestAuthor = $pr.user.login
            PullRequestState  = $pr.state
            MergedAt          = $pr.merged_at
            Reviewer          = $null
            ReviewState       = "NO_REVIEW"
            SubmittedAt       = $null
        }
    }

    # --------------------------------------
    # Reviews exist
    # --------------------------------------

    else {

        foreach ($review in $reviews) {

            $reviewResults += [PSCustomObject]@{
                Repository        = $repoName
                PullRequest       = $pr.number
                PullRequestAuthor = $pr.user.login
                PullRequestState  = $pr.state
                MergedAt          = $pr.merged_at
                Reviewer          = $review.user.login
                ReviewState       = $review.state
                SubmittedAt       = $review.submitted_at
            }
        }
    }
}

# -----------------------------
# Save results
# -----------------------------

$repositoryResults |
    ConvertTo-Json -Depth 5 |
    Set-Content ".\data\repositories.json"

$memberResults |
    ConvertTo-Json -Depth 5 |
    Set-Content ".\data\members.json"

$activityResults |
    ConvertTo-Json -Depth 5 |
    Set-Content ".\data\activity.json"

$reviewResults |
    ConvertTo-Json -Depth 5 |
    Set-Content ".\data\reviews.json"

if ($advisoryResults.Count -eq 0) {

    "[]" |
        Set-Content ".\data\advisories.json"
}
else {

    $advisoryResults |
        ConvertTo-Json -Depth 10 |
        Set-Content ".\data\advisories.json"
}

# -----------------------------
# Scan summary
# -----------------------------

Write-Host ""
Write-Host "============================================="
Write-Host "SCAN COMPLETE"
Write-Host "============================================="
Write-Host ""

Write-Host "Repositories: $($repositoryResults.Count)"
Write-Host "Member access records: $($memberResults.Count)"
Write-Host "Advisories: $($advisoryResults.Count)"
Write-Host "Activity records: $($activityResults.Count)"
Write-Host "Review records: $($reviewResults.Count)"

Write-Host ""
Write-Host "Output files:"
Write-Host "  .\data\repositories.json"
Write-Host "  .\data\members.json"
Write-Host "  .\data\advisories.json"
Write-Host "  .\data\activity.json"
Write-Host "  .\data\reviews.json"