#!/bin/bash

# exit on any error
set -e

# need to pass in the intended root password, the credentials, and the instance ID
if [ $# -lt 8 ]; then
    echo $0: usage: db_setup_script.sh [MysqlRootPassword] [Db] [User] [UserPass] [InstanceID] [MaintPassword] [masterIp] [otherIPs] 
    echo "Count was: " $#
	exit 1
fi
rootpass=$1
Db=$2
User=$3
UserPass=$4
instanceId=$5
maintPassword=$6
masterIp=$7
otherIps=$8

ipList=$( echo $otherIps | cut -d '[' -f 2 | cut -d ']' -f 1 );
port="3306"
replUserPassword=$UserPass

echo "ip list: " $ipList
echo "instance IP:" $masterIp
echo "instance ID: " $instanceId

echo "Checking for mariadb already installed"
if dpkg -s mariadb-server > /dev/null 2>&1; then
     echo "Package installed already - exiting"
     exit
else
     echo "Package not installed - proceeding"
fi

# get the apt keys for maria, retry 10 attempts before exiting.

retry=0
max=10
until [ $retry -ge $max ]
do
  sudo apt-key adv --recv-keys --keyserver hkp://keyserver.ubuntu.com:80 0xcbcb082a1bb943db && break 
  retry=$[$retry+1]
  sleep 5
  if [ $retry -eq $max ]
   then
    echo "KeyServer Issues. Exiting after '$max' failed attempts. Retry deployment after few minutes"
    exit 1
   fi
done

echo "Proceeding with db install"

# Set the root password so you don't have to interact
echo "mysql-server mysql-server/root_password password $1" | debconf-set-selections 
echo "mysql-server mysql-server/root_password_again password $1" | debconf-set-selections 

add-apt-repository 'deb http://mirror.jmu.edu/pub/mariadb/repo/10.1/ubuntu trusty main'

# install MariaDB database, Git (for MCS to deploy code from a git repo)
apt-get -y update
apt-get -y install mariadb-server git

# set the maintenance user's password
mysql -u root -p"$rootpass" -e "SET PASSWORD FOR 'debian-sys-maint'@'localhost' = PASSWORD('$maintPassword');"
sed -i 's/password = .*/password = '$maintPassword'/' /etc/mysql/debian.cnf

# need to explictly stop mysql as you can no longer stop it using service mysql stop
mysqladmin -u root -p"$rootpass" shutdown

rm -f /etc/mysql/conf.d/tokudb.cnf
rm -f /etc/mysql/conf.d/mysqld_safe_syslog.cnf
rm -f /etc/mysql/conf.d/mariadb.cnf

echo "Copying db server certs"

dbthumb='1DB9BF0D1676ADD878C29B2E63712486C65E04BC'
dbcathumb='64898C6AC2E8174258FB46438EE633DF10C78BED'
dbclientthumb='F9E19BF9DC45D5D56D26E782F48B1ED1A576EA43'

dbcertfilename=$dbthumb'.crt'
dbkeyfilename=$dbthumb'.prv'
dbcafilename=$dbcathumb'.crt'

dbclientcertfilename=$dbclientthumb'.crt'
dbclientkeyfilename=$dbclientthumb'.prv'

cp /var/lib/waagent/$dbcafilename /etc/mysql/ca-cert.crt 
cp /var/lib/waagent/$dbcertfilename /etc/mysql/server-cert.crt
cp /var/lib/waagent/$dbkeyfilename /etc/mysql/server-key.prv

openssl x509  -in /etc/mysql/ca-cert.crt -out /etc/mysql/ca-cert.pem -outform PEM
openssl x509  -in /etc/mysql/server-cert.crt -out /etc/mysql/server-cert.pem -outform PEM
openssl rsa  -in /etc/mysql/server-key.prv -out /etc/mysql/server-key.pem -outform PEM

#copy mariadb client ssl
echo "Copying client certs to /etc/mysql"

cp /var/lib/waagent/$dbclientcertfilename /etc/mysql/client-cert.crt
cp /var/lib/waagent/$dbclientkeyfilename /etc/mysql/client-key.prv

openssl x509  -in /etc/mysql/client-cert.crt -out /etc/mysql/client-cert.pem -outform PEM
openssl rsa  -in /etc/mysql/client-key.prv -out /etc/mysql/client-key.pem -outform PEM

chmod 440 /etc/mysql/*.pem
chown mysql:mysql /etc/mysql/*.pem
rm -f /etc/mysql/*.crt
rm -f /etc/mysql/*.prv

cat > "/etc/mysql/my.cnf" << EOF
### Include config files found in /etc/mysql/conf.d/
!includedir /etc/mysql/conf.d/
EOF

cat > "/etc/mysql/conf.d/mariadb.cnf" << EOF
[mysqld]
### Read Only ###
# Slaves should be set to 1, master 0
read_only                                = 1
### General ###
user                                     = mysql
pid-file                                 = /var/run/mysqld/mysqld.pid
socket                                   = /var/run/mysqld/mysqld.sock
basedir                                  = /usr
datadir                                  = /var/lib/mysql
tmpdir                                   = /tmp
lc_messages_dir                          = /usr/share/mysql
lc_messages                              = en_US
port                                     = ${port}
user                                     = mysql
character_set_server                     = utf8
collation_server                         = utf8_general_ci
optimizer_switch                         = 'index_merge=on,index_merge_union=on,index_merge_sort_union=on,index_merge_intersection=on,index_merge_sort_intersection=off,index_condition_pushdown=on,derived_merge=on,derived_with_keys=on,firstmatch=on,loosescan=on,materialization=on,in_to_exists=on,semijoin=on,partial_match_rowid_merge=on,partial_match_table_scan=on,subquery_cache=on,mrr=on,mrr_cost_based=on,mrr_sort_keys=off,outer_join_with_cache=on,semijoin_with_cache=on,join_cache_incremental=on,join_cache_hashed=on,join_cache_bka=on,optimize_join_buffer_size=on,table_elimination=on,extended_keys=on' 

### Safety and Security ###
bind_address                             = 0.0.0.0 # Set to InstanceIP
max_allowed_packet                       = 16M
max_connect_errors                       = 1000000
skip_name_resolve                        = 1
skip_external_locking                    = 1
sql_mode                                 = NO_ENGINE_SUBSTITUTION
sysdate_is_now                           = 1
interactive_timeout                      = 3600
back_log                                 = 100
symbolic_links                           = 0
secure_auth                              = ON
local_infile                             = 0
net_read_timeout                         = 30
net_write_timeout                        = 60
max_connections                          = 500
connect_timeout                          = 5
wait_timeout                             = 600

### Caches and Limits ###
tmp_table_size                           = 64M
max_heap_table_size                      = 64M
query_cache_type                         = 1
query_cache_size                         = 128M
query_cache_limit                        = 1M
thread_cache_size                        = 50
open_files_limit                         = 65535
table_definition_cache                   = 1024
table_open_cache                         = 1024

### InnoDB ###
default_storage_engine                   = InnoDB
innodb_stats_on_metadata                 = 0
innodb_stats_sample_pages                = 32
innodb_max_dirty_pages_pct               = 50 
transaction_isolation                    = READ-COMMITTED
innodb_support_xa                        = 0
innodb_flush_method                      = O_DIRECT
innodb_log_files_in_group                = 2
innodb_log_file_size                     = 1G
innodb_log_buffer_size                   = 64M
innodb_flush_log_at_trx_commit           = 1
innodb_file_per_table                    = 1
innodb_buffer_pool_size                  = 1G
innodb_open_files                        = 1024
innodb_lock_wait_timeout                 = 500
innodb_rollback_on_timeout               = 1
innodb_io_capacity                       = 2000

### Replication / Binary Logging ###
skip_slave_start                         = 0 
plugin_load                              = "semisync_master.so;semisync_slave.so"  
log_bin                                  = /var/log/mysql/mariadb-bin
log_bin_index                            = /var/log/mysql/mariadb-bin.index
relay_log                                = /var/log/mysql/relay-bin
relay_log_index                          = /var/log/mysql/relay-bin.index
relay_log_info_file                      = /var/log/mysql/relay-bin.info
server_id                                = ${instanceId} # pull from InstanceID, must be unique
binlog_format                            = ROW
expire_logs_days                         = 7
sync_binlog                              = 1
log_slave_updates                        = 1
slave_transaction_retries                = 10
relay_log_recovery                       = ON
sync_master_info                         = 1
sync_relay_log                           = 1
sync_relay_log_info                      = 1
binlog_stmt_cache_size                   = 128K
binlog_cache_size                        = 256K
slave_parallel_mode                      = optimistic  
slave_domain_parallel_threads            = 4 # Number of CPU cores 
slave_parallel_threads                   = 4 # Number of CPU cores 
gtid_domain_id                           = 0 
rpl_semi_sync_master                     = ON  
rpl_semi_sync_slave                      = ON  
loose_rpl_semi_sync_master_enabled       = ON  
loose_rpl_semi_sync_slave_enabled        = ON

### SSL ### 
ssl_ca                                   = /etc/mysql/ca-cert.pem
ssl_cert                                 = /etc/mysql/server-cert.pem
ssl_key                                  = /etc/mysql/server-key.pem

### Logging ###
log_warnings                             = 2
log_error                                = /var/log/mysql/mariadb-error.log
slow_query_log                           = 1
slow_query_log_file                      = /var/log/mysql/mariadb-slow.log
# log_queries_not_using_indexes            = 1  # Helpful to see exactly what queries aren't using indexes.
# log_slow_slave_statements                = 1
log_slow_verbosity                       = 'query_plan,innodb'
long_query_time                          = 1

###############
### Clients ###
###############
[mysqldump]
quick                                    = 1
quote_names                              = 1
max_allowed_packet                       = 16M

[client]
port                                     = ${port}
socket                                   = /var/run/mysqld/mysqld.sock
### SSL ### 
ssl_cert                                 = /etc/mysql/client-cert.pem
ssl_key                                  = /etc/mysql/client-key.pem
 
[mysqld_safe]
socket                                   = /var/run/mysqld/mysqld.sock
nice                                     = 0
skip_log_error                           = 1
syslog                                   = 1
EOF


# start the cluster (first instance initiates the cluster and creates the WP database and user)
if [ $instanceId = "1" ]; then 

    service mysql start
    # create the replication user
    mysql -u root -p"$rootpass" -e "GRANT REPLICATION SLAVE ON *.* TO 'repluser'@'%' IDENTIFIED BY '$replUserPassword';" 
    # create the User database and account
    mysql -u root -p"$rootpass" -e "create database $Db;create user '$User'@'%' identified by '$UserPass';grant all on $Db.* to '$User'@'%';"
    # disable read-only on master
    mysql -u root -p"$rootpass" -e "set global read_only=0" 
    sed -i 's/read_only                                = 1/read_only                                = 0/' /etc/mysql/conf.d/mariadb.cnf
    echo "master started"

else
    ### changed to use repluser instead of root
	verifystart=$(mysql -u repluser -p"$replUserPassword" -h "$masterIp" -P "$port" -ss -e "show global variables like 'read_only'; " | awk '{ print $2 }')
	if [ "$verifystart" != "OFF" ]; then
		until [ "$verifystart" == "OFF" ] ; do
			echo "waiting for master"
			sleep 2
			### changed to use repluser instead of root
			verifystart=$(mysql -u repluser -p"$replUserPassword" -h "$masterIp" -P "$port" -ss -e "show global variables like 'read_only';" | awk '{ print $2 }') 
		done
	fi
    service mysql start
	mysql -u root -p"$rootpass" -e "CHANGE MASTER TO master_host='"$masterIp"', master_port="$port", master_user='repluser', master_password='"$replUserPassword"', master_use_gtid=current_pos, master_ssl=1;"
	mysql -u root -p"$rootpass" -e "start slave"
    ### output to a log or somewhere to verify slave started successfully
	mysql -u root -p"$rootpass" -e "show slave status\G"
fi
