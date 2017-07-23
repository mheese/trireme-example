docker run \
  --name "Trireme" \
  --privileged \
  --net host \
  --pid host \
  -t \
  -v /var/run:/var/run \
aporeto/trireme-example deamon --remote
