#!/bin/bash
for ns in ns_pc1 ns_dev1 ns_dev2 ns_pc2; do
  ip netns del $ns 2>/dev/null || echo "$ns already gone"
done
echo "Done."
