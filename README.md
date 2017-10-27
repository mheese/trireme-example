# Trireme Example

This repo provides a simple implementation of network isolation using the
Trireme library in a standalone mode without any control plane. By default,
it implements the trireme policy interface with a simple static policy:

* Default Policy: Two containers can talk to each other if they have at least one label that matches.

The simple example also provides an illustration of how to integrate Trireme
with a more complex policy system. We demonstrate that by allowing Trireme to
load a policy configuration through a JSON file. An example of such policy
can be found the policy.json file.

# Trying it quickly

In order to get a quick proof of concept up and running, you can run the `launch.sh` script or run the following command:

```bash
docker run \
  --name "Trireme" \
  --privileged \
  --net host \
  --pid host \
  -t \
  -v /var/run:/var/run \
aporeto/trireme-example daemon --hybrid

```

This script will load a docker container in privileged and host mode that will run this example. Trireme
will be installed with remote enforcers and it is compatible with any networking technique that is
possible in the host machine, including IPVLAN/MacVLAN. The network isolation is even performed
when you are starting containers with the --net=host parameter in Docker (i.e. when containers
are started in the host namespace).

You can start a docker container with a specific label (in this case **app=web**)

```bash
docker run -l app=web -d nginx
```

A client will only be able to open a request to this container if it also has the same label ( **app=web** ). For example:

```bash
docker run -l app=web -it centos
curl http://<nginx-IP>
```
will succeed.

A client that starts with different label (for example **app=database**) will fail to connect:

```bash
docker run -l app=database -it centos
curl http://<nginx-IP>
```
fails.

# Building Trireme Example

If you want to build and try Trireme example with more advanced options and Linux Services
you need to follow these instructions. Please make sure that Go 1.8 is installed in
your machine. Trireme has some dependencies. libnetfilter-queue and ipset utilities
must be also installed and your OS must support iptables 1.6 or greater.

For example in an Ubuntu distribution:

```bash
sudo apt-get update
sudo apt-get install -y libnetfilter-queue1 iptables ipset
iptables -version
```

for Centos:
```bash
sudo yum update
sudo yum install libnetfilter_queue1 iptables ipset 
iptables -version
```

In order to build Trireme, simply do:

```bash
make build
```

This will output Trireme in the local directory. If you want to install it in a system
path try
```bash
make install
```

By default this installs trireme-example in /usr/local/bin. If you want to change the destination please
edit the Makefile and the BIN_PATH variable.

## Trying Trireme with any Linux process

Trireme supports any Linux process by extracting metadata from the Linux environment as
well as attributes supplied by the users. Trireme uses network cgroups (net_cls) capabilities
to isolate traffic from each process.

First, compile the Trireme example as in the previous section. Start Trireme in hybrid mode
supporting both Linux processes and containers at the same time. Optionally, you can
specify the networks that you want Trireme to apply (by default it will apply to all networks).
In the example below we apply Trireme only on the localhost traffic.

```bash
sudo trireme-example daemon --hybrid
```

Start an nginx server as a Linux process (make sure you have the nginx binary available at `/usr/sbin/nginx`, or adapt accordingly) :

```bash
sudo trireme-example run --ports=80 --label=app=web /usr/sbin/nginx  -- '-g daemon off;'
```

The above command starts the nginx server, listening on port 80. If you try to access this nginx
server with a curl command communication will fail. Note, that you need to supply to Trireme
the ports that your process will be listening. Now start with a curl command and associated
metadata:

```bash
trireme-example run --label=app=web /usr/bin/curl -- -p http://172.17.0.1
```
This command should succeed.

You can also start a docker container with the same metadata
```bash
docker run -l app=web -it centos
```

And you can access the nginx server at the host. However if you start the container
with different labels you will not able able to access the nginx container.

## Supporting host networking

Trireme isolation is also possible for containers that start with host networking. There are
several use cases where one might choose to do that, if they want to associate a static IP
address with a container or a similar function. For example, the API Router in Redhat OpenShift
uses the host network. When one uses the host network there is a big problem that the isolation
of network namespaces is lost. Trireme brings back some of this isolation and treats every
container differently, although they are possibly mapped in the same network namespace.

Let us assume that you Trireme running as in the previous example. You can start a docker
container with a specific label and attached to the host namespace:

```bash
docker run -l app=web --net=host -d nginx
```

In this case the nginx server is attached to the host network and can be accessed directly from
the host. If you try

```bash
curl http://127.0.0.1
```

The curl command will fail. Similarly, it will fail if you target it to the host bridge. The reason
is that Trireme still controls access to the container. However, if you try something like that:

```bash
docker run -l app=web -it centos
curl http://172.17.0.1
```

The curl command will succeed.

## Trying it with Docker Swarm

Trireme also has support for Docker Swarm including any overlay networks. This functionality is
based on a remote execution capability where Trireme will intercept traffic before any
of the libnetwork plugins even see the packets. This allows Trireme to support any of the
network plugins.


```bash
sudo trireme-example --remote --swarm
```

This activates Trireme with the remove enforcer capabilities and a Swarm specific
metadata extractor that will interpret metadata from Docker Swarm.

In your swarm cluster you can create an overlay network
```bash
docker network create --driver overlay mynet
```

Then you can create a two services:
```bash
docker service create  --network mynet --name web1 -l app=web nginx
docker service create --network mynet --name client -l app=web tester
```

Assuming that your tester container includes some curl capability, you can immediately
see that the tester can access the nginx server.

## Custom policy

The default operation of the example assumes that the policy will allow containers or
processes to exchange data if they have the same labels. However, the example offers
an alternative method where you can define a custom policy through a JSON configuration
file. Let's see an example of this policy:

```json
{
    "Web": {
        "ApplicationACLs": [
            {
                "Address": "192.30.253.0/24",
                "Policy": {
                    "Action": 1,
                    "PolicyID": "1",
                    "ServiceID": ""
                },
                "Port": "80",
                "Protocol": "TCP"
            },
            {
                "Address": "0.0.0.0/0",
                "Policy": {
                    "Action": 1,
                    "PolicyID": "4",
                    "ServiceID": ""
                },
                "Port": "53",
                "Protocol": "udp"
            }
        ],
        "NetworkACLs": [
            {
                "Address": "0.0.0.0/0",
                "Policy": {
                    "Action": 1,
                    "PolicyID": "7",
                    "ServiceID": ""
                },
                "Port": "",
                "Protocol": "icmp"
            }
        ],
        "TagSelectors": [
            {
                "Clause": [
                    {
                        "Key": "@usr:app",
                        "Operator": "=",
                        "Value": [
                            "web"
                        ]
                    }
                ],
                "Policy": {
                    "Action": 1,
                    "PolicyID": "8",
                    "ServiceID": ""
                }
            },
            {
                "Clause": [
                    {
                        "Key": "@usr:env",
                        "Operator": "=",
                        "Value": [
                            "dev"
                        ]
                    }
                ],
                "Policy": {
                    "Action": 1,
                    "PolicyID": "8",
                    "ServiceID": ""
                }
            }
        ]
    },
  }
  ```

In the above example, the name of the policy is "Web" and there are three main
sections:

1. `ApplicationACLs` describe what traffic the container can send to nodes that
are not protected by a Trireme process. The Trireme library defaults to ACLs if
the other nodes are not Trireme based. This is done by auto-detecting whether
the receiver of traffic is Trireme enabled and it responds with the proper
authorization headers. Note also, that by using ApplicationACLs we can allow
DNS traffic or other similar services. By default Trireme will block all other
traffic from the container.
2. `NetworkACLs` describes what traffic should be accepted if the other side
does not present any network authorization headers. In general this should be
avoided, but there are specific use cases that someone might want to achieve that.
3. `TagSelectors` describe the list of authorization policies that have be to
applied to the attributes of the identity. In the above example, traffic from
containers that have been identified as "@usr:app=web" or "@usr:env=dev" will
be accepted. Note here the use of the "@usr" prefix. This indicates that this is
a tag supplied by the user and can be trusted as long as the user can be trusted.
On the other hand a "@sys" prefixed tag indicates a tag that the system has
discovered and its generally trusted.

In order to load the policy to Trireme-Example you can need to define the file
with the --policy parameter.

# Understanding the simple example.

Trireme can be launched with a PresharedKey for authentication (the default mode of this example),
or can use a Public Key Infrastructure based on certificates. In both those cases, the constructors
package provides helpers that will instantiate Trireme with mostly default parameters. You can
launch Trireme with PKI by simply running with the --usePKI option after you generate the right
certificates. An example of self-signed certificates is provided in the certs directory.

## Trireme with PSK.

To instantiate Trireme, the following Helper is used:
```go
constructors.NewPSKTriremeWithDockerMonitor(serverID, networks, resolver, processor, eventCollector, syncAtStart, key)
```
The parameters are the following:
* `serverID` is a unique reference/name for the node where the instance of Trireme is running.
* `networks` is an array of CIDR networks that packets with those destinations are policed. In most of cases, giving the whole IP Space is a good default.
* `resolver` is a pointer to the PolicyResolver that implements the `trireme.PolicyResolver` interface. In this example this is the `CustomPolicyResolver` struct.
* `processor` is an optional reference
* `eventCollector` is an optional reference to a logger that collects all kind of events around your containers.
* `syncAtStart` is a bool that defines if the existing DockerContainers will have a policy applied at start time. In most of the cases, you want this to be enabled. In the example, we left it to false so that Docker containers running prior to Trireme coming up will be left untouched.
* `key` is an array of bytes that represent a PresharedKey.

The configurator returns a reference to Trireme and to the Monitor. Both of those references need to be explicitely started (with Start()) in order to start processing events.

## Trireme With PKI

For more complex use cases, Trireme can be used with a Private Key Infrastructure. In this case, each node will have a Private Key and associated Public Key cert signed by a recognized CA.

The configurator helper is similar to the PresharedKey one, except that it takes into input the PKI information:

```go
constructors.NewPKITriremeWithDockerMonitor(serverID, networks, resolver, processor, eventCollector, syncAtStart, keyPEM, certPEM, caCertPEM)
```

* `KeyPEM` is the Private Key in the PEM format.
* `CertPEM` is the Certificate for the current node. Must certify the ServerID name given as parameter
* `caCertPEM` is the CA that is used to validate all the Certificates of foreign nodes.

The implementation also provides a simple script for generating the necessary
certificates.


```bash
./create_certs.sh
```

