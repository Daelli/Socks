import socket
import struct
import select
import threading
import logging
import urllib.request
import urllib.error
from typing import Optional, Tuple
import time

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

class Socks5ProxyServer:
    def __init__(self, host: str = '0.0.0.0', port: int = 1080, 
                 username: str = None, password: str = None):
        """
        初始化SOCKS5代理服务器
        
        Args:
            host: 监听地址，0.0.0.0表示监听所有接口
            port: 监听端口
            username: 认证用户名
            password: 认证密码
        """
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.running = False
        self.server_socket = None
        
    def get_public_ip(self) -> str:
        """获取服务器的公网IP地址"""
        try:
            # 尝试多个获取公网IP的服务
            services = [
                'http://api.ipify.org',
                'http://icanhazip.com',
                'http://checkip.amazonaws.com',
                'http://ifconfig.me/ip',
                'http://ipinfo.io/ip',
                'http://ipecho.net/plain',
                'http://whatismyip.akamai.com',
                'http://myip.dnsomatic.com',
                'http://ident.me',
                'http://tnx.nl/ip'
            ]
            
            for service in services:
                try:
                    # 使用urllib替代requests
                    req = urllib.request.Request(
                        service,
                        headers={'User-Agent': 'Mozilla/5.0'}
                    )
                    with urllib.request.urlopen(req, timeout=3) as response:
                        if response.status == 200:
                            ip = response.read().decode('utf-8').strip()
                            if self.is_valid_ip(ip):
                                return ip
                except:
                    continue
            
            # 尝试获取本地IP
            try:
                # 尝试连接到外部服务器来获取本地IP
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                s.close()
                
                # 检查是否是公网IP
                if not local_ip.startswith(('10.', '172.16.', '172.17.', '172.18.', '172.19.', 
                                           '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', 
                                           '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', 
                                           '172.30.', '172.31.', '192.168.', '127.', '169.254.')):
                    return local_ip
                else:
                    return "需要手动查看公网IP"
                    
            except:
                return "需要手动查看公网IP"
                
        except Exception as e:
            logger.error(f"获取IP地址失败: {e}")
            return "需要手动查看公网IP"
    
    def is_valid_ip(self, ip: str) -> bool:
        """检查IP地址是否有效"""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            try:
                socket.inet_pton(socket.AF_INET6, ip)
                return True
            except socket.error:
                return False
    
    def generate_proxy_links(self, ip: str) -> dict:
        """生成各种格式的代理链接"""
        links = {}
        
        # 基础信息
        server_ip = ip
        port = self.port
        username = self.username or ""
        password = self.password or ""
        
        # 1. 标准 SOCKS5 链接
        if username and password:
            links['socks5'] = f"socks5://{username}:{password}@{server_ip}:{port}"
        else:
            links['socks5'] = f"socks5://{server_ip}:{port}"
        
        # 2. Telegram SOCKS5 代理链接
        if username and password:
            links['telegram'] = f"https://t.me/socks?server={server_ip}&port={port}&user={username}&pass={password}"
        else:
            links['telegram'] = f"https://t.me/socks?server={server_ip}&port={port}"
        
        # 3. 带备注的完整链接（用于分享）
        if username and password:
            links['share'] = f"socks5://{username}:{password}@{server_ip}:{port}/#{server_ip}-SOCKS5"
        else:
            links['share'] = f"socks5://{server_ip}:{port}/#{server_ip}-SOCKS5"
        
        # 4. 纯文本配置
        links['config'] = f"""服务器: {server_ip}
端口: {port}
用户名: {username or '无'}
密码: {password or '无'}
类型: SOCKS5"""
        
        return links
    
    def display_links(self, ip: str):
        """显示生成的代理链接"""
        print("\n" + "="*70)
        print("SOCKS5 代理服务器已启动！使用以下链接：")
        print("="*70)
        
        links = self.generate_proxy_links(ip)
        
        print("\n1. 标准SOCKS5链接：")
        print(f"   {links['socks5']}")
        
        print("\n2. Telegram一键导入链接：")
        print(f"   {links['telegram']}")
        print("   点击此链接或在Telegram中发送此链接即可自动配置")
        
        print("\n3. 分享链接：")
        print(f"   {links['share']}")
        
        print("\n4. 手动配置信息：")
        config_lines = links['config'].split('\n')
        for line in config_lines:
            print(f"   {line}")
        
        print("\n使用方法：")
        print("   1. Telegram: 点击上面的链接或发送给任意聊天")
        print("   2. 浏览器: 设置 -> 网络 -> 手动代理配置")
        print("   3. 命令行: curl --socks5 用户名:密码@IP:端口 URL")
        print("   4. 其他客户端: 使用SOCKS5代理，填写上面的服务器信息")
        print("="*70 + "\n")
        
        # 显示如何获取公网IP
        if "需要手动查看" in ip:
            print("注意：无法自动获取公网IP，请手动获取：")
            print("   1. 在浏览器访问: https://www.ipaddress.my/")
            print("   2. 或执行: curl ifconfig.me")
            print("   3. 然后用获取的IP替换上面的链接中的IP地址")
            print()
        
        print("提示：可以直接复制上面的链接使用")
        print()
        
    def get_local_ip(self) -> str:
        """获取本地IP地址"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return "127.0.0.1"
    
    def start(self):
        """启动SOCKS5代理服务器"""
        try:
            # 显示服务器信息
            print("\n" + "="*70)
            print("SOCKS5 代理服务器")
            print("="*70)
            
            print(f"监听地址: {self.host}:{self.port}")
            print(f"用户名: {self.username}")
            print(f"密码: {self.password}")
            print("="*70)
            
            # 获取本地IP
            local_ip = self.get_local_ip()
            print(f"本地IP: {local_ip}")
            
            # 获取公网IP
            print("\n正在获取公网IP地址...")
            public_ip = self.get_public_ip()
            print(f"公网IP: {public_ip}")
            
            # 显示链接
            self.display_links(public_ip)
            
            # 创建服务器socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.settimeout(5)
            
            # 绑定地址和端口
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            
            logger.info(f"SOCKS5代理服务器已启动")
            logger.info(f"监听地址: {self.host}:{self.port}")
            if self.username and self.password:
                logger.info(f"已启用认证: 用户名={self.username}, 密码={self.password}")
            else:
                logger.info("无认证模式")
            logger.info(f"本地IP: {local_ip}")
            if public_ip and public_ip != "需要手动查看公网IP":
                logger.info(f"公网IP: {public_ip}")
            logger.info("等待客户端连接...")
            
            # 主循环，接受客户端连接
            while self.running:
                try:
                    client_socket, client_addr = self.server_socket.accept()
                    logger.info(f"新连接来自: {client_addr[0]}:{client_addr[1]}")
                    
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, client_addr),
                        name=f"Client-{client_addr[0]}:{client_addr[1]}"
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        logger.error(f"接受连接时出错: {e}")
                        
        except Exception as e:
            logger.error(f"服务器启动失败: {e}")
        finally:
            self.stop()
    
    def stop(self):
        """停止服务器"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        logger.info("SOCKS5代理服务器已停止")
    
    def handle_client(self, client_socket: socket.socket, client_addr: tuple):
        """处理客户端连接"""
        try:
            if not self.negotiate_auth_method(client_socket):
                logger.warning(f"客户端 {client_addr} 认证方法协商失败")
                return
            
            if self.username and self.password:
                if not self.authenticate(client_socket):
                    logger.warning(f"客户端 {client_addr} 认证失败")
                    client_socket.close()
                    return
                logger.info(f"客户端 {client_addr} 认证成功")
            
            if not self.handle_request(client_socket, client_addr):
                logger.warning(f"客户端 {client_addr} 请求处理失败")
                return
                
        except Exception as e:
            logger.error(f"处理客户端 {client_addr} 时出错: {e}")
        finally:
            client_socket.close()
    
    def negotiate_auth_method(self, client_socket: socket.socket) -> bool:
        """协商认证方法"""
        try:
            data = client_socket.recv(2)
            if len(data) < 2:
                return False
            
            version, nmethods = struct.unpack('!BB', data[:2])
            
            if version != 5:
                return False
            
            if nmethods > 0:
                methods = client_socket.recv(nmethods)
            else:
                methods = b''
            
            if self.username and self.password:
                if 2 in methods:
                    response = struct.pack('!BB', 5, 2)
                else:
                    response = struct.pack('!BB', 5, 0xFF)
                    client_socket.send(response)
                    return False
            else:
                response = struct.pack('!BB', 5, 0)
                
            client_socket.send(response)
            return True
            
        except Exception as e:
            logger.error(f"协商认证方法失败: {e}")
            return False
    
    def authenticate(self, client_socket: socket.socket) -> bool:
        """用户名/密码认证"""
        try:
            data = client_socket.recv(2)
            if len(data) < 2:
                return False
            
            version, username_len = struct.unpack('!BB', data[:2])
            if version != 1:
                return False
            
            username = client_socket.recv(username_len).decode('utf-8', errors='ignore')
            
            password_len_data = client_socket.recv(1)
            if not password_len_data:
                return False
            password_len = struct.unpack('!B', password_len_data)[0]
            
            password = client_socket.recv(password_len).decode('utf-8', errors='ignore')
            
            if username == self.username and password == self.password:
                response = struct.pack('!BB', 1, 0)
                client_socket.send(response)
                return True
            else:
                response = struct.pack('!BB', 1, 1)
                client_socket.send(response)
                logger.warning(f"认证失败: 用户名={username}")
                return False
                
        except Exception as e:
            logger.error(f"认证过程出错: {e}")
            return False
    
    def handle_request(self, client_socket: socket.socket, client_addr: tuple) -> bool:
        """处理客户端请求"""
        try:
            data = client_socket.recv(4)
            if len(data) < 4:
                return False
            
            version, cmd, _, addr_type = struct.unpack('!BBBB', data[:4])
            
            if version != 5:
                return False
            
            if cmd != 1:
                self.send_response(client_socket, 7)
                return False
            
            target_addr = ""
            if addr_type == 1:
                addr_data = client_socket.recv(4)
                if len(addr_data) < 4:
                    return False
                target_addr = socket.inet_ntoa(addr_data)
                
            elif addr_type == 3:
                domain_len_data = client_socket.recv(1)
                if not domain_len_data:
                    return False
                domain_len = struct.unpack('!B', domain_len_data)[0]
                target_addr = client_socket.recv(domain_len).decode('utf-8', errors='ignore')
                
            elif addr_type == 4:
                addr_data = client_socket.recv(16)
                if len(addr_data) < 16:
                    return False
                try:
                    target_addr = socket.inet_ntop(socket.AF_INET6, addr_data)
                except:
                    self.send_response(client_socket, 8)
                    return False
            else:
                self.send_response(client_socket, 8)
                return False
            
            port_data = client_socket.recv(2)
            if len(port_data) < 2:
                return False
            target_port = struct.unpack('!H', port_data)[0]
            
            logger.info(f"客户端 {client_addr[0]}:{client_addr[1]} 请求连接: {target_addr}:{target_port}")
            
            remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote_socket.settimeout(10)
            
            try:
                if addr_type == 3:
                    try:
                        addr_info = socket.getaddrinfo(target_addr, target_port, 
                                                       socket.AF_UNSPEC, socket.SOCK_STREAM)
                        if not addr_info:
                            raise socket.error("无法解析域名")
                        
                        for res in addr_info:
                            af, socktype, proto, canonname, sa = res
                            try:
                                remote_socket = socket.socket(af, socktype, proto)
                                remote_socket.settimeout(10)
                                remote_socket.connect(sa)
                                break
                            except socket.error:
                                if remote_socket:
                                    remote_socket.close()
                                continue
                        else:
                            raise socket.error("无法连接到目标服务器")
                            
                    except Exception as e:
                        logger.error(f"无法解析或连接 {target_addr}:{target_port}: {e}")
                        self.send_response(client_socket, 4)
                        return False
                else:
                    remote_socket.connect((target_addr, target_port))
                
                bind_addr, bind_port = remote_socket.getsockname()
                
                if ':' in bind_addr:
                    addr_bytes = socket.inet_pton(socket.AF_INET6, bind_addr)
                    response = struct.pack('!BBBB', 5, 0, 0, 4) + addr_bytes + struct.pack('!H', bind_port)
                else:
                    addr_bytes = socket.inet_aton(bind_addr)
                    response = struct.pack('!BBBB', 5, 0, 0, 1) + addr_bytes + struct.pack('!H', bind_port)
                
                client_socket.send(response)
                
                logger.info(f"连接建立成功: {client_addr[0]}:{client_addr[1]} -> {target_addr}:{target_port}")
                
                self.forward_data(client_socket, remote_socket, client_addr, target_addr, target_port)
                
            except socket.timeout:
                logger.error(f"连接目标服务器超时: {target_addr}:{target_port}")
                self.send_response(client_socket, 4)
                return False
            except ConnectionRefusedError:
                logger.error(f"连接被拒绝: {target_addr}:{target_port}")
                self.send_response(client_socket, 5)
                return False
            except Exception as e:
                logger.error(f"连接目标服务器失败 {target_addr}:{target_port}: {e}")
                self.send_response(client_socket, 1)
                return False
            finally:
                if remote_socket:
                    remote_socket.close()
                
            return True
            
        except Exception as e:
            logger.error(f"处理请求失败: {e}")
            return False
    
    def send_response(self, client_socket: socket.socket, rep: int):
        """发送响应给客户端"""
        try:
            response = struct.pack('!BBBB', 5, rep, 0, 1) + socket.inet_aton('0.0.0.0') + struct.pack('!H', 0)
            client_socket.send(response)
        except Exception as e:
            logger.error(f"发送响应失败: {e}")
    
    def forward_data(self, client_socket: socket.socket, remote_socket: socket.socket, 
                     client_addr: tuple, target_addr: str, target_port: int):
        """转发数据"""
        sockets = [client_socket, remote_socket]
        total_sent = 0
        total_received = 0
        
        try:
            while True:
                readable, _, exceptional = select.select(sockets, [], sockets, 60)
                
                if exceptional:
                    break
                
                for sock in readable:
                    try:
                        data = sock.recv(8192)
                        if not data:
                            logger.info(f"连接关闭: {client_addr[0]}:{client_addr[1]} -> {target_addr}:{target_port}")
                            logger.info(f"传输统计: 发送={total_sent}字节, 接收={total_received}字节")
                            return
                        
                        if sock is client_socket:
                            remote_socket.send(data)
                            total_sent += len(data)
                        else:
                            client_socket.send(data)
                            total_received += len(data)
                            
                    except (ConnectionResetError, BrokenPipeError):
                        logger.info(f"连接断开: {client_addr[0]}:{client_addr[1]} -> {target_addr}:{target_port}")
                        logger.info(f"传输统计: 发送={total_sent}字节, 接收={total_received}字节")
                        return
                    except Exception as e:
                        logger.error(f"数据转发错误: {e}")
                        return
                        
        except (select.error, socket.error, OSError) as e:
            logger.info(f"连接结束: {client_addr[0]}:{client_addr[1]} -> {target_addr}:{target_port}")
            logger.info(f"传输统计: 发送={total_sent}字节, 接收={total_received}字节")
        except Exception as e:
            logger.error(f"转发数据时出错: {e}")

def main():
    """主函数，启动SOCKS5服务器"""
    # 使用指定的配置
    HOST = "0.0.0.0"
    PORT = 10524
    USERNAME = "whatthefuck"
    PASSWORD = "whatthefuck"
    
    print("正在启动 SOCKS5 代理服务器...")
    print("配置信息:")
    print(f"  监听地址: {HOST}:{PORT}")
    print(f"  用户名: {USERNAME}")
    print(f"  密码: {PASSWORD}")
    print()
    print("按 Ctrl+C 停止服务器")
    print()
    
    # 创建并启动服务器
    server = Socks5ProxyServer(
        host=HOST,
        port=PORT,
        username=USERNAME,
        password=PASSWORD
    )
    
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n正在停止服务器...")
        server.stop()
    except Exception as e:
        print(f"服务器启动失败: {e}")

if __name__ == '__main__':
    main()
