#!/usr/bin/env bash
# AWS Bedrock's own CloudWatch usage for amazon.nova-lite (last 15 min).
R=us-east-1; M=amazon.nova-lite-v1:0
S=$(date -u -v-15M +%Y-%m-%dT%H:%M:%S); E=$(date -u +%Y-%m-%dT%H:%M:%S)
q(){ aws cloudwatch get-metric-statistics --region "$R" --namespace AWS/Bedrock \
  --metric-name "$1" --dimensions Name=ModelId,Value="$M" \
  --start-time "$S" --end-time "$E" --period 900 --statistics Sum \
  --query 'Datapoints[].Sum' --output text; }
printf "nova-lite   invocations=%s   input_tokens=%s\n" "$(q Invocations)" "$(q InputTokenCount)"
