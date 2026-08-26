# =============================================
# GitHub Security & Access Analysis
# =============================================

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "============================================="
Write-Host " GitHub Security & Access Analysis"
Write-Host "============================================="
Write-Host ""

# ---------------------------------------------
# Load scanner results
# ---------------------------------------------

$repositories = Get-Content ".\data\repositories.json" -Raw |
    ConvertFrom-Json

$members = Get-Content ".\data\members.json" -Raw |
    ConvertFrom-Json

$advisories = Get-Content ".\data\advisories.json" -Raw |
    ConvertFrom-Json

$activity = Get-Content ".\data\activity.json" -Raw |
    ConvertFrom-Json

$reviews = @(
    Get-Content ".\data\reviews.json" -Raw |
        ConvertFrom-Json
)

Write-Host "Repositories loaded      : $($repositories.Count)"
Write-Host "Member access records    : $($members.Count)"
Write-Host "Advisories loaded        : $($advisories.Count)"
Write-Host "Activity records loaded  : $($activity.Count)"
Write-Host "Review records loaded    : $($reviews.Count)"

# ---------------------------------------------
# Security Findings
# ---------------------------------------------

$findings = @()

# ---------------------------------------------
# Check 1: Public repositories
# ---------------------------------------------

foreach ($repo in $repositories) {

    if ($repo.Private -eq $false) {

        $findings += [PSCustomObject]@{
            Repository     = $repo.Repository
            FindingType    = "Public Repository"
            Severity       = "Medium"
            Description    = "Repository is publicly visible."
            Recommendation = "Review whether public visibility is required. Use private visibility for repositories containing sensitive code, configuration, or security-related material."
        }
    }
}

# ---------------------------------------------
# Check 2: Elevated access for non-owner members
# ---------------------------------------------

foreach ($member in $members) {

    # Repository owner is expected to have administrative access.
    if ($member.Login -eq "mani1234543") {
        continue
    }

    if ($member.Admin -eq $true) {

        $findings += [PSCustomObject]@{
            Repository     = $member.Repository
            FindingType    = "Administrative Access"
            Severity       = "High"
            Description    = "$($member.Login) has administrative access to the repository."
            Recommendation = "Review whether administrative access is required. Apply least privilege and remove unnecessary administrative permissions."
        }
    }
    elseif ($member.Push -eq $true) {

        $findings += [PSCustomObject]@{
            Repository     = $member.Repository
            FindingType    = "Write-Level Access"
            Severity       = "Medium"
            Description    = "$($member.Login) has write-level access to the repository."
            Recommendation = "Review whether write access is required. Apply least-privilege access and remove unnecessary write permissions."
        }
    }
}

# ---------------------------------------------
# Check 3: Empty repositories
# ---------------------------------------------

foreach ($repo in $repositories) {

    if ($repo.Empty -eq $true) {

        $findings += [PSCustomObject]@{
            Repository     = $repo.Repository
            FindingType    = "Empty Repository"
            Severity       = "Low"
            Description    = "Repository contains no commits and may require cleanup or lifecycle review."
            Recommendation = "Confirm whether the repository is still required. Archive or remove unused repositories according to organizational policy."
        }
    }
}

# ---------------------------------------------
# Check 4: Dependabot vulnerabilities
# ---------------------------------------------

foreach ($advisory in $advisories) {

    $severity = $advisory.Severity

    if ($severity -eq "critical") {
        $findingSeverity = "Critical"
    }
    elseif ($severity -eq "high") {
        $findingSeverity = "High"
    }
    elseif ($severity -eq "moderate") {
        $findingSeverity = "Medium"
    }
    elseif ($severity -eq "low") {
        $findingSeverity = "Low"
    }
    else {
        $findingSeverity = "Medium"
    }

    $findings += [PSCustomObject]@{
        Repository     = $advisory.Repository
        FindingType    = "Dependabot Vulnerability"
        Severity       = $findingSeverity
        Description    = "Dependency $($advisory.Package) has a $severity severity security advisory."
        Recommendation = "Review and remediate the vulnerable dependency. Update the affected package to a secure version and verify that the vulnerability is resolved."
    }
}

# ---------------------------------------------
# Check 5: Repository activity
# ---------------------------------------------

foreach ($record in $activity) {

    if ($record.CommitCount -eq 0) {

        $findings += [PSCustomObject]@{
            Repository     = $record.Repository
            FindingType    = "No Recent Repository Activity"
            Severity       = "Low"
            Description    = "No commits were detected during the configured lookback period."
            Recommendation = "Confirm whether the repository is still required. Archive or remove unused repositories according to organizational policy."
        }
    }
}

# ---------------------------------------------
# Check 6: Merged PR without approval
# ---------------------------------------------

foreach ($review in $reviews) {

    if (
        $review.PullRequestState -eq "closed" -and
        $null -ne $review.MergedAt -and
        $review.ReviewState -ne "APPROVED"
    ) {

        $findings += [PSCustomObject]@{
            Repository     = $review.Repository
            FindingType    = "Merged PR Without Approval"
            Severity       = "High"
            Description    = "Pull request #$($review.PullRequest) was merged without an approved review."
            Recommendation = "Require at least one approved code review before merging pull requests, especially for security-sensitive repositories."
        }
    }
}

# ---------------------------------------------
# Check 7: Self-reviewed pull request
# ---------------------------------------------

foreach ($review in $reviews) {

    if (
        $review.PullRequestAuthor -eq $review.Reviewer -and
        $review.ReviewState -eq "APPROVED"
    ) {

        $findings += [PSCustomObject]@{
            Repository     = $review.Repository
            FindingType    = "Self-Reviewed Pull Request"
            Severity       = "High"
            Description    = "Pull request #$($review.PullRequest) was approved by its own author."
            Recommendation = "Require an independent reviewer and prevent authors from approving their own pull requests."
        }
    }
}

# ---------------------------------------------
# Findings summary
# ---------------------------------------------

Write-Host ""
Write-Host "Security findings generated: $($findings.Count)"

foreach ($finding in $findings) {

    Write-Host ""
    Write-Host "[$($finding.Severity)] $($finding.FindingType)"
    Write-Host "Repository: $($finding.Repository)"
    Write-Host "Description: $($finding.Description)"
}

# ---------------------------------------------
# Generate security report
# ---------------------------------------------

$findings |
    ConvertTo-Json -Depth 10 |
    Set-Content ".\reports\security-report.json"

$findings |
    Export-Csv ".\reports\security-report.csv" -NoTypeInformation

Write-Host ""
Write-Host "Security reports generated:"
Write-Host "  .\reports\security-report.json"
Write-Host "  .\reports\security-report.csv"

# ---------------------------------------------
# Severity summary
# ---------------------------------------------

$criticalCount = @(
    $findings | Where-Object Severity -eq "Critical"
).Count

$highCount = @(
    $findings | Where-Object Severity -eq "High"
).Count

$mediumCount = @(
    $findings | Where-Object Severity -eq "Medium"
).Count

$lowCount = @(
    $findings | Where-Object Severity -eq "Low"
).Count

Write-Host ""
Write-Host "Severity Summary"
Write-Host "----------------"
Write-Host "Critical: $criticalCount"
Write-Host "High:     $highCount"
Write-Host "Medium:   $mediumCount"
Write-Host "Low:      $lowCount"
Write-Host "Total:    $($findings.Count)"

Write-Host ""
Write-Host "============================================="
Write-Host " ASSESSMENT COMPLETE"
Write-Host "============================================="