# NounHub Infrastructure

## Resource Naming Conventions

- Tables use feature-based prefixes (e.g., `feed_post_table`, `feed_category_table`)
- Common resources like user table remain unprefixed
- Resource names include environment (stack) suffix: `resource-name-${stack}`

## DynamoDB Configuration

- All tables use on-demand billing mode (`PAY_PER_REQUEST`)
- No provisioned capacity management required
- Cost based on actual usage rather than provisioned capacity 

## JWT Token Handling

- Parse token once per request
- Store groups in `GroupMap` for O(1) permission checks
- Pass Claims object to handlers to avoid repeated parsing 