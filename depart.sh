#!/bin/bash
DFL_KEYGLITCH_LOG="keyglitch.log"
DFL_OUTPUT="departed.txt"
BUSTER="./f00d-partial-buster"
DFL_CRCKR_INP="samples.txt"

[[ "$1" != "" ]] && DFL_KEYGLITCH_LOG="$1"
[[ "$2" != "" ]] && DFL_CRCKR_INP="$2"
[[ "$3" != "" ]] && DFL_OUTPUT="$3"

ref=$(grep 'cause=clean' $DFL_KEYGLITCH_LOG)
[[ "$ref" == "" ]] && echo "No clean ref found" && exit 1
[[ $(echo "$ref" | wc -l) -gt 1 ]] && echo "Multiple clean refs/dirty log!" && exit 1

if [[ $(echo "$ref" | grep 'partials') == "" ]]; then
    echo "No partials found in clean ref - simply sorting the samples"
    seed=$(echo "$ref" | awk -F"seed=" '{print $2}' | awk -F, '{print $1}')
    echo "SEED: $seed"
    ref=$(echo "$ref" | awk -F"data=" '{print $2}' | awk -F: '{print $1}')
    echo "CLEAN: $ref"
    echo "$ref" > $DFL_CRCKR_INP
    grep 'bad_decrypt' $DFL_KEYGLITCH_LOG | grep -v 'af_op=3' | awk -F"data=" '{print $2}' | awk -F: '{print $1}' | sort -u >> $DFL_CRCKR_INP
    echo "$(cat $DFL_CRCKR_INP | wc -l) samples saved to $DFL_CRCKR_INP"
    exit 0
fi

#get unique partials
partials=$(cat $DFL_KEYGLITCH_LOG | grep 'partials' | awk -F"partials=" '{print $2}' | awk '{print $1}' | sort -u) # 3CA0B9D0AEBE1DF598E33215721988BD:6019E8AB959C1207EB98D2D6:F04EC49EDF3CA55C:CB0B5E8B
while IFS= read -r partial; do
    echo "Processing partial: $partial"
    if [[ $(cat $DFL_OUTPUT | grep $partial) != "" ]]; then
        echo "Partial $partial already in output file"
        continue
    fi
    ret=$(echo $partial | tr ':' ' ' | xargs $BUSTER --decrypt-partial --decrypt-key)
    if [[ "$ret" == *"calculated key:"* ]]; then
        key=$(echo $ret | grep 'calculated key:' | awk '{print $3}')
        echo "found key $key for partial $partial"
        echo "$partial,$key" >> $DFL_OUTPUT
    else
        echo "failed to find key for partial $partial"
        echo "$partial," >> $DFL_OUTPUT
    fi
done <<< "$partials"

#bust the ref
ref=$(cat $DFL_KEYGLITCH_LOG | grep -m1 'cause=clean' | awk -F"partials=" '{print $2}' | awk '{print $1}')
echo "Processing ref: $ref"
ret=$(echo $ref | tr ':' ' ' | xargs $BUSTER --decrypt-partial --decrypt-key)
if [[ "$ret" == *"calculated key:"* ]]; then
    key=$(echo $ret | grep 'calculated key:' | awk '{print $3}')
    echo "found ref: $key"
else
    echo "failed ref $ref"
    exit 1
fi

echo $key > $DFL_CRCKR_INP
cat $DFL_OUTPUT | awk -F"," '{print $2}' >> $DFL_CRCKR_INP