## AWS CLOUD SOLUTION FOR 2 COMPANY WEBSITES USING A REVERSE PROXY TECHNOLOGY ##

We will build a secure infrastructure inside AWS VPC (Virtual Private Cloud) network for  __narbyd Company__ that uses WordPress CMS for its main business website, and a [Tooling](https://github.com/dybran/tooling) website for the DevOps team.

As part of the company’s desire for improved security and performance, a decision has been made to use a reverse proxy technology from NGINX to achieve this.

__PURPOSE:__

Reduced Cost, increase Security and Scalability are the major requirements for this project. Hence, implementing the architecture designed below, ensure that infrastructure for both websites (WordPress and Tooling) are resilient to Web Server failures, can accomodate increased traffic and at the same time, has reasonable cost.

__AWS resources Required for the Design:__

- North Virginia Region (us-east-1)
- Availibility zones (3 subnets in us-east-1a) and (3 subnets in us-east-1b)
- VPC Network Range - __10.0.0.0/16__
- subnets - __10.0.1.0/24, 10.0.2.0/24, 10.0.3.0/24, 10.0.4.0/24, 10.0.5.0/24__ and __10.0.6.0/24__
- 6 subnets (4 private subnets and 2 public subnets)
- internet gateway
- 2 nginx for reverse proxy
- 2 bastion hosts/jump servers
- 2 application Load balancers(ALB)
- Auto scaling Groups to manage the scaling of the Ec2 instances
- 2 NAT gateways for the resources in the private subnet to communicate with the internet gateway.
  
__N/B:__ The NAT gateway only allows traffic to the internet and does not allow from the internet.

- Route DNS
- RDS for the database
- Amazon Elastic Files System for the file management


__AWS MULTIPLE WEBSITE PROJECT__

![](./images/tooling_project_15.png)

__SET UP A VIRTUAL PRIVATE NETWORK (VPC)__

Create VPC

![](./images/vpc1.PNG)
![](./images/vpc2.PNG)
![](./images/vpc3.PNG)
![](./images/vpc4.PNG)
![](./images/vpc5.PNG)


Create subnets as shown in the architecture - 3 subnets in each Availability zones i.e __10.0.1.0/24, 10.0.3.0/24, 10.0.5.0/24__ in __us-east-1a__

![](./images/sub1.PNG)
![](./images/sub2.PNG)
![](./images/sub3.PNG)
![](./images/s.PNG)


And 3 subnets in Availability zone __us-east-1b__ i.e __10.0.2.0/24, 10.0.4.0/24, 10.0.6.0/24__

![](./images/s1.PNG)
![](./images/s2.PNG)

__N/B:__ These subnets are neither private nor public at this point. The Internet gateway and NAT gateway associated with any of them identifies them private or public.

Create a route table and associate it with public subnets

![](./images/rt.PNG)
![](./images/rt1.PNG)
![](./images/rt2.PNG)
![](./images/rt3.PNG)
![](./images/rt4.PNG)

Create a route table and associate it with private subnets

![](./images/rts.PNG)
![](./images/rts1.PNG)
![](./images/rts2.PNG)
![](./images/rts3.PNG)

Create an __Internet Gateway__ for the public subnet

![](./images/ig.PNG)

Attach the internet gateway to the VPC

![](./images/ig1.PNG)
![](./images/ig2.PNG)
![](./images/ig5.PNG)

Edit a route in public route table and associate it with the Internet Gateway. This allows the public subnet to be accessible from the Internet)

![](./images/edit1.PNG)
![](./images/edit2.PNG)
![](./images/edit3.PNG)
![](./images/edit4.PNG)

Create 3 Elastic IPs - 1 Elastic IP will be used by the NAT gatewayw hile the remaining @ will be used by the Bastion host.

![](./images/q.PNG)

Create a NAT Gateway and assign one of the Elastic IPs. The NAT gateway is created in the public subnet

![](./images/nat1.PNG)
![](./images/nat2.PNG)
![](./images/nat3.PNG)
![](./images/nat4.PNG)

Edit a route in private route table, and associate it with the NAT Gateway. This allows traffic to be sent to the internet but not from the internet.

![](./images/t1.PNG)
![](./images/t2.PNG)
![](./images/t3.PNG)

Create a Security Group for Application Load Balancer - Access to ALB will be allowed from the internet

![](./images/alb.PNG)
![](./images/qa.PNG)

Create security group for Bastion Servers - Access to the Bastion servers should be allowed only from workstations that need to SSH into the bastion servers. Hence, you can use your workstation public IP address.

We can get this by opening the CMD in our local workstation(computer)
and run the command `ipconfig`

![](./images/bas.PNG)

Create security group from Application LB access will only be available from the Internet

![](./images/albsg.PNG)

Security Group for webservers - Access to Webservers should only be allowed from webserver ALB and bastion host.

![](./images/qaw.PNG)

__N/B:__ We can choose to allow __ssh__ only from the Bastion host's IP. This will mean that if the Ec2 instance is compromised them the access is lost.

This is not a good practice when applying auto scaling since it will scale out and scaling when needed and access to other Ec2 instances is denied to the bastion host.

![](./images/12.PNG)
![](./images/123.PNG)

Create a Security Group for Nginx Servers - Access to Nginx should only be allowed from a Application Load balancer (ALB) and bastion host.

![](./images/ng.PNG)
![](./images/ngx1.PNG)

Create security group for the internal ALB - allow access to only nginx reverse proxy.

![](./images/lb1.PNG)
![](./images/lb2.PNG)

Create security group for the backend services or datalayer to allow the websever access to the RDS and EFS in the backend security group. Allow access to the bastion host.

![](./images/asd.PNG)

Purchase a domain name and Create an ACM certificate

![](./images/ac.PNG)

Create record for both __tooling__ and __wordpress__

For tooling

![](./images/crq1.PNG)
![](./images/crq2.PNG)

For Wordpress

![](./images/crw.PNG)

__SETUP ELASTIC FILE SYSTEM (EFS)__

Create EFS

![](./images/efs1.PNG)
![](./images/efs2.PNG)
![](./images/efs3.PNG)
![](./images/efs4.PNG)

We will set up the mount target to be able to acces the webservers in subnet 3 (10.0.3.0/24) and subnet 4 (10.0.4.0/24)

![](./images/efs5.PNG)
![](./images/efs6.PNG)
![](./images/efs8.PNG)

We need to create access points for the EFS.
Our design has two websites. If we create one accesspoint for the two websites, the files will overwrite each other. So we will create access point for __Tooling__ and __Wordpress__

Access point for __wordpress__

![](./images/efs9.PNG)
![](./images/wp1.PNG)
![](./images/wp2.PNG)
![](./images/wp4.PNG)

We will do same for access point for __tooling__

![](./images/acc.PNG)


__SETUP AMAZON RELATIONAL DATABASE SYSTEM__

To set the RDS up, we need to Create a __KMS key__ from __Key Management Service (KMS)__ to be used to encrypt the database instance.

![](./images/kms1.PNG)
![](./images/kms2.PNG)
![](./images/kms3.PNG)
![](./images/kms4.PNG)
![](./images/kms5.PNG)
![](./images/kms6.PNG)
![](./images/kms7.PNG)
![](./images/kms8.PNG)

Amazon Relational Database Service (Amazon RDS) is a managed distributed relational database service by Amazon Web Services. This web service running in the cloud designed to simplify setup operations, maintance & scaling of relational databases.

To ensure that the databases are highly available and also have failover support in case one availability zone fails, we will configure a multi-AZ set up of RDS MySQL database instance. Since we are only using 2 AZs we can only failover to one but the same concept applies to 3 Availability Zones.

Configure RDS

Create a subnet group and add 2 private subnets (backend or data Layer)

![](./images/sb1.PNG)
![](./images/sb2.PNG)
![](./images/sb3.PNG)

Select the availability zones (us-east-1a and us-east-1b) and the subnets of the RDS from the design

![](./images/sb4.PNG)
![](./images/sb5.PNG)

Create RDS

![](./images/rds1.PNG)
![](./images/rds2.PNG)

The __production__ and __dev/test__ allows you encrypt the database using __KMS key__. We will be selecting the __free tier__ in the __mysql__ engine for the purpose of this project so as to save cost.

![](./images/rds3.PNG)
![](./images/rds4.PNG)
![](./images/rds5.PNG)
![](./images/rds6.PNG)
![](./images/rds7.PNG)
![](./images/rds8.PNG)
![](./images/rds9.PNG)
![](./images/rds10.PNG)


__SET UP COMPUTE RESOURCES__
We will be setting up the __AMI__ for the nginx, bastion and webservers for their various __Auto Scaling Groups__.

Launch  3 RHEL-8 instances - The AMIs will be used for the ASG. Lauch the instances in the default VPC.

![](./images/lau.PNG)

__For Bastion Host__

Run the following commands

`$ sudo yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm`

`$ sudo yum install -y dnf-utils http://rpms.remirepo.net/enterprise/remi-release-8.rpm`

`$ sudo yum install wget vim python3 telnet htop git mysql net-tools chrony -y`

`$ sudo systemctl start chronyd` 

`$ sudo systemctl enable chronyd`

`$ sudo systemctl status chronyd`

![](./images/b1.PNG)
![](./images/b2.PNG)
![](./images/b3.PNG)
![](./images/b4.PNG)

__For Nginx__

Run the followinf commands

`$ sudo yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm`

`$ sudo yum install -y dnf-utils http://rpms.remirepo.net/enterprise/remi-release-8.rpm`

`$ sudo yum install wget vim python3 telnet htop git mysql net-tools chrony -y`

`$ sudo systemctl start chronyd` 

`$ sudo systemctl enable chronyd`

`$ sudo systemctl status chronyd`

![](./images/so1.PNG)
![](./images/so2.PNG)
![](./images/so3.PNG)
![](./images/so4.PNG)

Configure Selinux policies

`$ sudo setsebool -P httpd_can_network_connect=1`

`$ sudo setsebool -P httpd_can_network_connect_db=1`

`$ sudo setsebool -P httpd_execmem=1`

`$ sudo setsebool -P httpd_use_nfs 1`

![](./images/ss.PNG)

Install amazon efs utils for mounting the target on the Elastic file system

`$ git clone https://github.com/aws/efs-utils`

`$ cd efs-utils`

`$ sudo yum install -y make`

`$ sudo yum install -y rpm-build`

`$ sudo make rpm` 

`$ sudo yum install -y  ./build/amazon-efs-utils*rpm`

![](./images/mount1.PNG)
![](./images/mount2.PNG)
![](./images/mount3.PNG)
![](./images/mount4.PNG)

Setting up self-signed certificate for the nginx instance. If a target group is configured with the HTTPS protocol or uses HTTPS health checks, the TLS connections to the targets use the security settings from the ELBSecurityPolicy-2016-08 policy. The load balancer establishes TLS connections with the targets using certificates that you install on the targets. The load balancer does not validate these certificates. Therefore, you can use self-signed certificates or certificates that have expired. Because the load balancer is in a virtual private cloud (VPC), traffic between the load balancer and the targets is authenticated at the packet level, so it is not at risk of man-in-the-middle attacks or spoofing even if the certificates on the targets are not valid.

`$ sudo mkdir /etc/ssl/private`

`$ sudo chmod 700 /etc/ssl/private`

`$ sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/narbyd.key -out /etc/ssl/certs/narbyd.crt`

`$ sudo openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048`

![](./images/self.PNG)

To confirm my cert installation is successful and present in the server

`$ sudo ls -l /etc/ssl/certs/`

`$ sudo ls -l /etc/ssl/private/`

![](./images/certsn.PNG)

Start and enable __nginx__

![](./images/Capture.PNG)

__For Webserver__

Run the following commands to configure the webserver instance.

`$ sudo yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm`

`$ sudo yum install -y dnf-utils http://rpms.remirepo.net/enterprise/remi-release-8.rpm`

`$ sudo yum install wget vim python3 telnet htop git mysql net-tools chrony -y`

`$ sudo systemctl start chronyd`

`$ sudo systemctl enable chronyd`

`$ sudo systemctl status chronyd`

![](./images/wb1.PNG)
![](./images/wb2.PNG)
![](./images/wb3.PNG)

Configure Selinux policies

`$ sudo setsebool -P httpd_can_network_connect=1`

`$ sudo setsebool -P httpd_can_network_connect_db=1`

`$ sudo setsebool -P httpd_execmem=1`

`$ sudo setsebool -P httpd_use_nfs 1`

![](./images/x.PNG)

Install amazon efs utils for mounting the target on the Elastic file system

`$ git clone https://github.com/aws/efs-utils`

`$ cd efs-utils`

`$ sudo yum install -y make`

`$ sudo yum install -y rpm-build`

`$ sudo make rpm` 

`$ sudo yum install -y  ./build/amazon-efs-utils*rpm`

![](./images/x1.PNG)
![](./images/x2.PNG)
![](./images/x3.PNG)
![](./images/x4.PNG)

setting up self-signed certificate for the apache webserver instance

`$ sudo yum install -y mod_ssl`

`$ sudo openssl req -newkey rsa:2048 -nodes -keyout /etc/pki/tls/private/narbyd.key -x509 -days 365 -out /etc/pki/tls/certs/narbyd.crt`

![](./images/n1.PNG)
![](./images/n2.PNG)

Using vi editor to edit the SSL certificate file path from __localhost.crt__ and __localhost.key__ to __narbyd.crt__ and __narbyd.key__ respectively

`$ sudo vi /etc/httpd/conf.d/ssl.conf`

![](./images/nx1.PNG)

Creating the AMIs for __Webserver, Bastion and Nginx__

Select __Instance > Action > Image and Templates > Create Image__

![](./images/ci1.PNG)
![](./images/ci2.PNG)
![](./images/ci3.PNG)
![](./images/c4.PNG)
![](./images/ci5.PNG)

__Configuring Target Groups__

For Nginx Server

- Selecting Instances as the target type
- Ensuring the protocol HTTPS on secure TLS port 443
- Ensuring that the health check path is __/healthstatus__

![](./images/hs1.PNG)
![](./images/hs2.PNG)
![](./images/hs3.PNG)

For Wordpress

- Selecting Instances as the target type
- Ensuring the protocol HTTPS on secure TLS port 443
- Ensuring that the health check path is __/healthstatus__

For Tooling

- Selecting Instances as the target type
- Ensuring the protocol HTTPS on secure TLS port 443
- Ensuring that the health check path is __/healthstatus__
  
![](./images/re.PNG)

__Configuring Application Load Balancer (ALB)__

Create the ALB forwarding traffic to the Nginx reverse proxy

![](./images/11.PNG)
![](./images/12.PNG)
![](./images/13.PNG)
![](./images/14.PNG)
![](./images/15.PNG)
![](./images/16.PNG)
![](./images/17.PNG)

Create the ALB forwarding traffic to the Webservers
![](./images/01.PNG)
![](./images/02.PNG)

We have 2 target groups - tooling and wordpress. We have to set one of them as default. Lets set wordpress as the default.

![](./images/03.PNG)
![](./images/04.PNG)
![](./images/05.PNG)

We go to the __listeners__ to set rules for the the tooling target group

![](./images/li1.PNG)
![](./images/li2.PNG)
![](./images/li3.PNG)
![](./images/li4.PNG)
![](./images/li5.PNG)
![](./images/li6.PNG)
![](./images/li7.PNG)

__Creating A Launch Template__

For Bastion

![](./images/lt1.PNG)
![](./images/lt2.PNG)
![](./images/lt3.PNG)
![](./images/lt4.PNG)
![](./images/lt5.PNG)
![](./images/lt6.PNG)
![](./images/lt7.PNG)

Similar configuration for the nginx launch template.

For the Nginx, we need to create __reverse.conf__ file. This will be used to configure to have access to the __webserver ALB__ .

Create a __reverse.conf__ file and add the following code snippet

```
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log;
pid /run/nginx.pid;

# Load dynamic modules. See /usr/share/doc/nginx/README.dynamic.
include /usr/share/nginx/modules/*.conf;

events {
    worker_connections 1024;
}

http {
    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';

    access_log  /var/log/nginx/access.log  main;

    sendfile            on;
    tcp_nopush          on;
    tcp_nodelay         on;
    keepalive_timeout   65;
    types_hash_max_size 2048;

    
    default_type        application/octet-stream;

    # Load modular configuration files from the /etc/nginx/conf.d directory.
    # See http://nginx.org/en/docs/ngx_core_module.html#include
    # for more information.
    include /etc/nginx/conf.d/*.conf;

     server {
        listen       80;
        listen       443 http2 ssl;
        listen       [::]:443 http2 ssl;
        root          /var/www/html;
        server_name  *.mydevopsproject.top;
        
        
        ssl_certificate /etc/ssl/certs/narbyd.crt;
        ssl_certificate_key /etc/ssl/private/narbyd.key;
        ssl_dhparam /etc/ssl/certs/dhparam.pem;

      

        location /healthstatus {
        access_log off;
        return 200;
       }
    
         
        location / {
            proxy_set_header             Host $host;
            proxy_pass                   https://internal-narbyd-webserver-ALB-1635565532.us-east-1.elb.amazonaws.com/; 
        }
    }
}
```

Push to the github so we can use it to set up the nginx launch template

`$ git add .`

`$ git commit -m "added reverse.conf file"`

`$ git push`

Create the Nginx ALB to use the __reverse.conf__ file through the user data.

![](./images/gi1.PNG)
![](./images/gi3.PNG)

For the Wordpress

We configure the wordpress using the user data. First we mount the EFS access point of the wordpress using the user data configurations.

![](./images/ap1.PNG)
![](./images/ap2.PNG)

Wordpress userdata

```
#!/bin/bash

#mount wordpress acces point
mkdir /var/www/
sudo mount -t efs -o tls,accesspoint=fsap-075d969a83a54d104 fs-039addedc443b6916:/ /var/www/

#Install httpd
yum install -y httpd 
systemctl start httpd
systemctl enable httpd

#install dependencies
yum module reset php -y
yum module enable php:remi-7.4 -y
yum install php php-common php-mbstring php-opcache php-intl php-xml php-gd php-curl php-mysqlnd php-fpm php-json -y
systemctl start php-fpm
systemctl enable php-fpm

#download wordpress
wget http://wordpress.org/latest.tar.gz

#setup wordpress
tar xzvf latest.tar.gz
rm -rf latest.tar.gz
cp wordpress/wp-config-sample.php wordpress/wp-config.php
mkdir /var/www/html/
cp -R /wordpress/* /var/www/html/

#create healthstatus file
cd /var/www/html/
touch healthstatus

#changing the localhost to RDS endpoint
sed -i "s/localhost/narbyd-database.cwndedhlcmgg.us-east-1.rds.amazonaws.com/g" wp-config.php

#set up the username and password 
sed -i "s/username_here/narbyd/g" wp-config.php 
sed -i "s/password_here/sa4la2xa/g" wp-config.php 
sed -i "s/database_name_here/wordpressdb/g" wp-config.php 
chcon -t httpd_sys_rw_content_t /var/www/html/ -R
systemctl restart httpd
```

![](./images/wt1.PNG)
![](./images/wt2.PNG)
![](./images/wt3.PNG)
![](./images/wt4.PNG)
![](./images/wt5.PNG)

![](./images/sac.PNG)

For Tooling

We will create the lauch template using the user data below

```
#!/bin/bash
mkdir /var/www/
sudo mount -t efs -o tls,accesspoint=fsap-0c6229307091b5b33 fs-039addedc443b6916:/ /var/www/
yum install -y httpd 
systemctl start httpd
systemctl enable httpd
yum module reset php -y
yum module enable php:remi-7.4 -y
yum install -y php php-common php-mbstring php-opcache php-intl php-xml php-gd php-curl php-mysqlnd php-fpm php-json
systemctl start php-fpm
systemctl enable php-fpm
git clone https://github.com/dybran/tooling.git
mkdir /var/www/html
cp -R /tooling/html/*  /var/www/html/
cd /tooling
mysql -h narbyd-database.cwndedhlcmgg.us-east-1.rds.amazonaws.com -u narbyd -p toolingdb < tooling-db.sql
cd /var/www/html/
touch healthstatus
sed -i "s/$db = mysqli_connect('mysql.tooling.svc.cluster.local', 'admin', 'admin', 'tooling');/$db = mysqli_connect('narbyd-database.cwndedhlcmgg.us-east-1.rds.amazonaws.com', 'narbyd', 'sa4la2xa', 'toolingdb');/g" functions.php
chcon -t httpd_sys_rw_content_t /var/www/html/ -R
systemctl restart httpd
```
![](./images/ud.PNG)
![](./images/ud2.PNG)


__Creating the Auto Scaling Group__

We will create the auto scaling group using the lauch templates.

For Bastion

![](./images/asgb1.PNG)
![](./images/asgb2.PNG)
![](./images/asgb3.PNG)
![](./images/asgb4.PNG)
![](./images/asgb5.PNG)
![](./images/asgb6.PNG)

For Nginx

![](./images/asgn1.PNG)
![](./images/asgn2.PNG)

Check if it is __Healthy__

1[](./images/heal.PNG)

Before creating the Auto Scaling Group for the webservers, we will go into the RDS and create the wordpress database

Copy the __.prem key__ into the bastion host

![](./images/scp1.PNG)

Connect remotely to the RDs from the bastion host

`$ mysql -h narbyd-database.cwndedhlcmgg.us-east-1.rds.amazonaws.com -u narbyd -p`

![](./images/mys.PNG)
![](./images/too.PNG)

Create Auto Scaling Group for webserver wordpress and tooling respectively.

For wordpress

![](./images/asgw.PNG)
![](./images/asgw2.PNG)
![](./images/asgw3.PNG)

For tooling

![](./images/asgt1.PNG)

![](./images/all.PNG)


__N/B:__ Check for the health status of the tooling, wordpress, nginx and bastion ASG

We can use `$ telnet <private-IP-address or DNS> <port-number> to check for connectivity between servers.

The ASG launches the Ec2 Instances from the launch templates

![](./images/inst.PNG)

Open the browser __incognito__ using __"CTRL + SHIFT + n"__ and paste the domain name i.e `wordpress.mydevopsproject.top` 

![](./images/111.PNG)
![](./images/112.PNG)
![](./images/113.PNG)

or `tooling.mydevopsproject.top`

![](./images/tooling.PNG)

