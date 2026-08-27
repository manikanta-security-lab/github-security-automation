# GitHub Security & Access Automation
# Contribution Analysis & Access Hygiene Scoring
# Demonstration project for manikanta-security-lab

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "============================================="
Write-Host " GitHub Contribution & Access Analysis"
Write-Host "============================================="
Write-Host ""

# --------------------------------------------------
# Load scanner output
# --------------------------------------------------

$membersJson = Get-Content ".\data\members.json" -Raw
$activityJson = Get-Content ".\data\activity.json" -Raw
$reviewsJson = Get-Content ".\data\reviews.json" -Raw
$repositoriesJson = Get-Content ".\data\repositories.json" -Raw

$members = @((ConvertFrom-Json -InputObject $membersJson))
$activity = @((ConvertFrom-Json -InputObject $activityJson))
$reviews = @((ConvertFrom-Json -InputObject $reviewsJson))
$repositories = @((ConvertFrom-Json -InputObject $repositoriesJson))

# Explicitly unwrap JSON arrays
if ($members.Count -eq 1 -and $members[0] -is [System.Array]) {
    $members = @($members[0])
}

if ($activity.Count -eq 1 -and $activity[0] -is [System.Array]) {
    $activity = @($activity[0])
}

if ($reviews.Count -eq 1 -and $reviews[0] -is [System.Array]) {
    $reviews = @($reviews[0])
}

if ($repositories.Count -eq 1 -and $repositories[0] -is [System.Array]) {
    $repositories = @($repositories[0])
}

Write-Host "Members loaded       : $($members.Count)"
Write-Host "Activity records     : $($activity.Count)"
Write-Host "Review records       : $($reviews.Count)"
Write-Host "Repositories loaded  : $($repositories.Count)"
Write-Host ""

# --------------------------------------------------
# Scoring model
# --------------------------------------------------
#
# Commits authored     : 40
# PRs opened           : 20
# PRs merged           : 15
# Reviews submitted    : 15
# Recent activity      : 10
#
# High   = 80-100
# Medium = 50-79
# Low    = 1-49
# None   = 0
#
# Access removal is NEVER automatic.
# Only a human-review recommendation is generated.
#
# --------------------------------------------------

$ContributionResults = @()
$AccessRecommendations = @()

foreach ($repo in $repositories) {

    $repoName = $repo.Repository

    Write-Host "---------------------------------------------"
    Write-Host "Analyzing repository: $repoName"
    Write-Host "---------------------------------------------"

    # --------------------------------------------------
    # Get members for this repository
    # --------------------------------------------------

    $repoMembers = @(
        $members | Where-Object {
            $_.Repository -eq $repoName
        }
    )

    # --------------------------------------------------
    # Get repository activity
    # --------------------------------------------------

    $repoActivity = @(
        $activity | Where-Object {
            $_.Repository -eq $repoName
        }
    )

    # --------------------------------------------------
    # Get PR/review records
    # --------------------------------------------------

    $repoReviews = @(
        $reviews | Where-Object {
            $_.Repository -eq $repoName
        }
    )

    foreach ($member in $repoMembers) {

        $username = $member.Login

        # --------------------------------------------------
        # Permission
        # --------------------------------------------------

        if ($member.Admin -eq $true) {
            $permission = "admin"
        }
        elseif ($member.Maintain -eq $true) {
            $permission = "maintain"
        }
        elseif ($member.Push -eq $true) {
            $permission = "write"
        }
        elseif ($member.Triage -eq $true) {
            $permission = "triage"
        }
        else {
            $permission = "read"
        }

        # --------------------------------------------------
        # Commit contribution
        # --------------------------------------------------
        #
        # activity.json currently contains repository-level
        # commit count and LatestCommitter.
        #
        # We only attribute the repository commit count when
        # the recorded LatestCommitter matches this member.
        #
        # This avoids falsely assigning repository activity
        # to every member.
        # --------------------------------------------------

        $commitCount = 0
        $latestActivity = $null

        foreach ($record in $repoActivity) {

            if ($record.LatestCommitter -eq $username) {
                $commitCount = [int]$record.CommitCount
                $latestActivity = $record.LatestCommitAt
            }
        }

        # --------------------------------------------------
        # PRs opened
        # --------------------------------------------------

        $prsOpened = @(
            $repoReviews |
            Where-Object {
                $_.PullRequestAuthor -eq $username
            } |
            Select-Object -ExpandProperty PullRequest -Unique
        ).Count

        # --------------------------------------------------
        # PRs merged
        # --------------------------------------------------

        $prsMerged = @(
            $repoReviews |
            Where-Object {
                $_.PullRequestAuthor -eq $username -and
                $null -ne $_.MergedAt
            } |
            Select-Object -ExpandProperty PullRequest -Unique
        ).Count

        # --------------------------------------------------
        # Reviews submitted
        # --------------------------------------------------

        $reviewsSubmitted = @(
            $repoReviews |
            Where-Object {
                $_.Reviewer -eq $username -and
                $_.ReviewState -and
                $_.ReviewState -ne "NO_REVIEW"
            }
        ).Count

        # --------------------------------------------------
        # Score: commits
        # --------------------------------------------------

        if ($commitCount -ge 20) {
            $commitPoints = 40
        }
        else {
            $commitPoints = [math]::Min(
                40,
                ($commitCount * 2)
            )
        }

        # --------------------------------------------------
        # Score: PRs opened
        # --------------------------------------------------

        $prOpenedPoints = [math]::Min(
            20,
            ($prsOpened * 5)
        )

        # --------------------------------------------------
        # Score: PRs merged
        # --------------------------------------------------

        $prMergedPoints = [math]::Min(
            15,
            ($prsMerged * 5)
        )

        # --------------------------------------------------
        # Score: reviews
        # --------------------------------------------------

        $reviewPoints = [math]::Min(
            15,
            ($reviewsSubmitted * 5)
        )

        # --------------------------------------------------
        # Score: recent activity
        # --------------------------------------------------

        $recentActivityPoints = 0

        if ($latestActivity) {

            try {

                $activityDate = [datetime]$latestActivity

                $daysSince =
                    ([datetime]::UtcNow - $activityDate.ToUniversalTime()).Days

                if ($daysSince -le 30) {
                    $recentActivityPoints = 10
                }
                elseif ($daysSince -le 90) {
                    $recentActivityPoints = 7
                }
                elseif ($daysSince -le 180) {
                    $recentActivityPoints = 4
                }
            }
            catch {
                $recentActivityPoints = 0
            }
        }

        # --------------------------------------------------
        # Final score
        # --------------------------------------------------

        $score =
            $commitPoints +
            $prOpenedPoints +
            $prMergedPoints +
            $reviewPoints +
            $recentActivityPoints

        # --------------------------------------------------
        # Contribution level
        # --------------------------------------------------

        if ($score -ge 80) {
            $level = "High"
        }
        elseif ($score -ge 50) {
            $level = "Medium"
        }
        elseif ($score -gt 0) {
            $level = "Low"
        }
        else {
            $level = "None"
        }

        # --------------------------------------------------
        # Store contribution result
        # --------------------------------------------------

        $ContributionResults += [PSCustomObject]@{

            Repository = $repoName
            Member = $username
            Permission = $permission

            CommitsAuthored = $commitCount
            PullRequestsOpened = $prsOpened
            PullRequestsMerged = $prsMerged
            ReviewsSubmitted = $reviewsSubmitted

            LastActivity = $latestActivity

            CommitPoints = $commitPoints
            PROpenedPoints = $prOpenedPoints
            PRMergedPoints = $prMergedPoints
            ReviewPoints = $reviewPoints
            RecentActivityPoints = $recentActivityPoints

            ContributionScore = $score
            ContributionLevel = $level
        }

        # --------------------------------------------------
        # Access recommendation
        # --------------------------------------------------
        #
        # Admins/owners are NEVER recommended for removal.
        #
        # Low/no activity members are flagged for HUMAN REVIEW.
        #
        # No automatic removal is performed.
        # --------------------------------------------------

        if ($member.Admin -eq $true) {
            continue
        }

        if ($score -le 20) {

            if ($score -eq 0) {
                $reason =
                    "No measurable contribution activity was detected during the configured lookback period."
            }
            else {
                $reason =
                    "Low contribution score based on available commits, pull requests, reviews, and recent activity."
            }

            $AccessRecommendations += [PSCustomObject]@{

                Repository = $repoName
                Member = $username
                Permission = $permission

                ContributionScore = $score
                ContributionLevel = $level

                Recommendation = "REVIEW_ACCESS"

                Reason = $reason

                AutomaticRemoval = $false
            }
        }
    }
}

# --------------------------------------------------
# Write JSON outputs
# --------------------------------------------------

$ContributionResults |
    ConvertTo-Json -Depth 10 |
    Set-Content ".\data\contributions.json"

$AccessRecommendations |
    ConvertTo-Json -Depth 10 |
    Set-Content ".\data\access-recommendations.json"

# --------------------------------------------------
# Display results
# --------------------------------------------------

Write-Host ""
Write-Host "============================================="
Write-Host " CONTRIBUTION ANALYSIS COMPLETE"
Write-Host "============================================="
Write-Host ""

Write-Host "Contribution records     : $($ContributionResults.Count)"
Write-Host "Access recommendations   : $($AccessRecommendations.Count)"
Write-Host ""

Write-Host "Scoring model:"
Write-Host "  Commits authored       : 40 points"
Write-Host "  PRs opened             : 20 points"
Write-Host "  PRs merged             : 15 points"
Write-Host "  Reviews submitted      : 15 points"
Write-Host "  Recent activity        : 10 points"
Write-Host "  Maximum score          : 100"
Write-Host ""

Write-Host "Contribution levels:"
Write-Host "  High                   : 80-100"
Write-Host "  Medium                 : 50-79"
Write-Host "  Low                    : 1-49"
Write-Host "  None                   : 0"
Write-Host ""

Write-Host "Important:"
Write-Host "  Access removal is recommendation-only."
Write-Host "  Repository admins are excluded."
Write-Host ""

Write-Host "Output files:"
Write-Host "  .\data\contributions.json"
Write-Host "  .\data\access-recommendations.json"
Write-Host ""

Write-Host "============================================="
Write-Host " ASSESSMENT COMPLETE"
Write-Host "============================================="