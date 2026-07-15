#!/usr/bin/env bash
# AWS Bedrock's own CloudWatch usage for amazon.nova-pro, counted from a fixed
# start marker (written once at demo start) so the total only grows.
R=us-east-1; M=amazon.nova-pro-v1:0
S=$(cat /tmp/busbar_demo_start 2>/dev/null || date -u -v-10M +%Y-%m-%dT%H:%M:%S)
E=$(date -u +%Y-%m-%dT%H:%M:%S)
q(){ aws cloudwatch get-metric-statistics --region "$R" --namespace AWS/Bedrock \
  --metric-name "$1" --dimensions Name=ModelId,Value="$M" \
  --start-time "$S" --end-time "$E" --period 3600 --statistics Sum \
  --query 'Datapoints[].Sum' --output text | awk '{s+=$1} END{printf "%d", s}'; }
printf "nova-pro   invocations=%s   input_tokens=%s\n" "$(q Invocations)" "$(q InputTokenCount)"
