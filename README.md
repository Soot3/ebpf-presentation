# ebpf-presentation
This is a code repository for the files used in my Conf42 observability presentation


## Requirements
This setups up clang and ebpf packages for your environment

```shell
sudo apt update
sudo apt install clang llvm libc6-dev-i386 libbpf-dev xdp-tools linux-headers-$(uname -r) 
```

## First Demo: Packet Logger
- Compile and Attach the ebpf program

```shell
clang -O2 -g -Wall -target bpf -c packet_logger/logger.c -o packet_logger/logger.o
sudo xdp-loader load -m skb lo packet_logger/logger.o
```

- Check that it was successfully attached

```shell
sudo xdp-loader status lo
```

- Test the program

```shell
ping -I lo 127.0.0.1
```

The program will log traffic with info on the packet received.
This information is saved in a BPF map.
Check it out. Maps created would be "packet_counters" and "packet_events" 

```shell
sudo bpftool map list
```
```shell
sudo bpftool map dump id <map_id>
```
These maps can be processed by userspace programs and compiled with
observability tools.

## Second Demo: File Tracer (Python BCC)

We will be using nginx as a web service and tracking access to the 
nginx files.

- Install Nginx 

```shell
sudo apt-get install -y nginx

sudo systemctl start nginx
sudo systemctl enable nginx
```

- Test nginx is running
```shell 
sudo systemctl status nginx
curl http://localhost
```

- Create html files
```shell
sudo mkdir -p /var/www/html/test
echo "Test page 1" | sudo tee /var/www/html/test/page1.html
echo "Test page 2" | sudo tee /var/www/html/test/page2.html
echo "Test page 3" | sudo tee /var/www/html/test/page3.html
```
- Run the program
```shell
sudo python3 openat_tracing/trace_py.py
```
- Test from another terminal or machine

```shell
# Access main page
curl http://localhost/

# Access test pages
curl http://localhost/test/page1.html
curl http://localhost/test/page2.html
curl http://localhost/test/page3.html

# Access directory listing
curl http://localhost/test/

# Access status page (triggers config file reads)
curl http://localhost/status
```
Here's a script for load testing

```shell
for i in {1..100}; do
  curl http://localhost/test/page$((i % 3 + 1)).html &>/dev/null
  sleep 0.05
done
```

