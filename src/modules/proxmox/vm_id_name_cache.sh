# current unixtime
UNIXTIMENOW=$(date +%s)

# get VM ids and names
vm_ids=$(/usr/sbin/qm list | awk '{print $1}' | grep -P "\d")

get_vm_name_from_id() {
    local vm_id="$1"
    /usr/sbin/qm config $vm_id | grep '^name:' | awk '{print $2}'
}

for vm_id in ${vm_ids}; do
    vm_name=$(get_vm_name_from_id "${vm_id}")
    echo "${vm_id}=${vm_name}"
    /usr/bin/curl "http://gl_lookup.geek4u.net:8080/?lookup=cache_key_value&key=pve_vm_id:::${vm_id}&value=${vm_name}"
done

# get LXC ids and names
lxc_ids=$(pct list | awk '{print $1","$3}')
i=0
for line in ${lxc_ids}; do
    if ((i > 0)); then
        # echo $line
        IN=$line
        arrIN=(${IN//,/ })
        vm_id=${arrIN[0]}
        vm_name=${arrIN[1]}
        echo "${vm_id}=${vm_name}"
        /usr/bin/curl "http://gl_lookup.geek4u.net:8080/?lookup=cache_key_value&key=pve_vm_id:::${vm_id}&value=${vm_name}"
    fi
    ((i++))
done

# cleanup
# prefix = pve_vm_id:::
# older_than_unixtime = $UNIXTIMENOW
# http://localhost:8080/?lookup=cleanup_stale_key_value&prefix=pve_vm_id&older_than_unixtime=2712937202
/usr/bin/curl "http://gl_lookup.geek4u.net:8080/?lookup=cleanup_stale_key_value&prefix=pve_vm_id&older_than_unixtime=${UNIXTIMENOW}"
