---
inclusion: always
---

# AWS CLI Best Practices for Kiro

## Pagination and Output Control

### Always Use Non-Interactive Parameters

To avoid delays from pagination prompts (`--more--`), always include parameters that ensure continuous output:

#### Critical Parameter: `--no-paginate`

**ALWAYS add `--no-paginate` to AWS CLI commands** to prevent interactive pagination:

```bash
# Good - prevents --more-- prompts
aws logs get-log-events --log-group-name "/aws/lambda/function-name" --log-stream-name "stream-name" --no-paginate --limit 10

# Good - combines no-paginate with limits
aws logs describe-log-streams --log-group-name "/aws/lambda/function-name" --no-paginate --max-items 5

# Avoid - can get stuck at --more-- prompt
aws logs get-log-events --log-group-name "/aws/lambda/function-name" --log-stream-name "stream-name"
```

#### Recommended Patterns:

**CloudWatch Logs:**
```bash
# Good - limits output and avoids pagination
aws logs get-log-events --log-group-name "/aws/lambda/function-name" --log-stream-name "stream-name" --no-paginate --limit 10

# Good - uses start-time to limit scope
aws logs get-log-events --log-group-name "/aws/lambda/function-name" --log-stream-name "stream-name" --no-paginate --start-time 1766105000000

# Avoid - can trigger pagination
aws logs get-log-events --log-group-name "/aws/lambda/function-name" --log-stream-name "stream-name"
```

**List Operations:**
```bash
# Good - limits results
aws logs describe-log-streams --log-group-name "/aws/lambda/function-name" --no-paginate --max-items 5

# Good - uses query to limit output
aws cloudfront list-distributions --no-paginate --query 'DistributionList.Items[0:3].[Id,DomainName]' --output table

# Avoid - can return large datasets
aws logs describe-log-streams --log-group-name "/aws/lambda/function-name"
```

**CloudWatch Metrics:**
```bash
# Good - specific time range and period
aws cloudwatch get-metric-statistics --namespace AWS/Lambda --metric-name Invocations --no-paginate --start-time 2025-12-19T00:00:00Z --end-time 2025-12-19T23:59:59Z --period 3600 --statistics Sum

# Good - limits datapoints with shorter time range
aws cloudwatch get-metric-statistics --namespace AWS/CloudWatch --metric-name Requests --no-paginate --start-time 2025-12-19T10:00:00Z --end-time 2025-12-19T11:00:00Z --period 300 --statistics Sum
```

### Parameters to Always Include:

- **`--no-paginate`** - CRITICAL: Prevents interactive pagination prompts
- `--limit N` or `--max-items N` for list operations
- `--start-time` and `--end-time` for time-based queries
- `--query` to filter and limit output fields
- `--output table` for readable formatting of small datasets
- `--period` for appropriate granularity in metrics

### Commands That Commonly Cause Pagination Issues:

- `aws logs get-log-events` (without --limit)
- `aws logs describe-log-streams` (without --max-items)
- `aws cloudwatch get-metric-statistics` (with large time ranges)
- `aws s3 ls` (for buckets with many objects)
- `aws lambda list-functions` (in accounts with many functions)
- `aws cloudformation describe-stack-events` (without --max-items)

### Quick Reference:

| Command Type | Always Add | Example |
|--------------|------------|---------|
| **ALL Commands** | `--no-paginate` | `aws logs get-log-events --no-paginate --limit 10` |
| Log Events | `--no-paginate --limit 10` | `aws logs get-log-events --no-paginate --limit 10` |
| List Operations | `--no-paginate --max-items 5` | `aws logs describe-log-streams --no-paginate --max-items 5` |
| Metrics | `--no-paginate --period 3600` + time range | `aws cloudwatch get-metric-statistics --no-paginate --period 3600 --start-time ...` |
| Large Lists | `--no-paginate --query` filter | `aws s3 ls --no-paginate --query 'Contents[0:10]'` |

## Performance Tips

- **ALWAYS use `--no-paginate`** to prevent interactive prompts
- Use `--query` to extract only needed fields
- Combine `--output table` with `--query` for readable results
- Use specific time ranges instead of open-ended queries
- Prefer `--max-items` over processing large result sets

## Universal AWS CLI Pattern

**Every AWS CLI command should follow this pattern:**
```bash
aws [service] [operation] --no-paginate [other-parameters]
```

This ensures smooth, uninterrupted interactions with AWS CLI commands.