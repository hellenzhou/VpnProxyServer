import hilog from '@ohos.hilog';
import vpn_server from 'libvpn_server.so';

interface ServerStats {
  packetsReceived: number;
  packetsSent: number;
  bytesReceived: number;
  bytesSent: number;
  lastActivity: string;
  connectedClients: ClientInfo[];
}

interface ClientInfo {
  ip: string;
  port: number;
  lastSeen: string;
  packetsCount: number;
  totalBytes: number;
}

interface TestData {
  enabled: boolean;
  interval: number;
  message: string;
  targetClient: string;
}

interface PacketData {
  timestamp: string;
  client: string;
  data: string;
  hex: string;
  type: string;
}

@Entry
@Component
struct Index {
  @State port: string = '8888';
  @State status: string = 'stopped';
  @State isRunning: boolean = false;
  @State logs: string[] = [];
  @State stats: ServerStats = {
    packetsReceived: 0,
    packetsSent: 0,
    bytesReceived: 0,
    bytesSent: 0,
    lastActivity: 'No activity',
    connectedClients: []
  };
  @State testData: TestData = {
    enabled: false,
    interval: 1000,
    message: 'VPN Test Message',
    targetClient: ''
  };
  @State dataBuffer: string[] = [];
  @State showHexView: boolean = false;
  @State lastDataCount: number = 0;
  private statsTimer?: number;
  private testTimer?: number;

  private addLog(message: string): void {
    // 使用手动格式化时间，避免 toLocaleTimeString() 的互斥锁问题
    const now: Date = new Date();
    const hours: string = String(now.getHours()).padStart(2, '0');
    const minutes: string = String(now.getMinutes()).padStart(2, '0');
    const seconds: string = String(now.getSeconds()).padStart(2, '0');
    const timestamp: string = `${hours}:${minutes}:${seconds}`;
    this.logs.unshift(`[${timestamp}] ${message}`);
    if (this.logs.length > 20) {
      this.logs = this.logs.slice(0, 20);
    }
  }

  private resetStats(): void {
    this.stats = {
      packetsReceived: 0,
      packetsSent: 0,
      bytesReceived: 0,
      bytesSent: 0,
      lastActivity: 'No activity',
      connectedClients: []
    };
    this.dataBuffer = [];
    this.lastDataCount = 0;
  }

  private toHex(str: string): string {
    let hex: string = '';
    for (let i: number = 0; i < str.length; i++) {
      hex += str.charCodeAt(i).toString(16).padStart(2, '0') + ' ';
    }
    return hex.trim();
  }

  private start(): void {
    const p: number = Number(this.port);
    if (isNaN(p) || p <= 0 || p > 65535) {
      this.status = 'Invalid port number';
      this.addLog('ERROR: Invalid port number');
      return;
    }
    
    const ret: number = vpn_server.startServer(p);
    if (ret === 0) {
      this.status = 'running';
      this.isRunning = true;
      this.addLog(`UDP Server started on port ${p}`);
      this.resetStats();
      this.startStatsUpdate();
    } else {
      this.status = `start failed: ${ret}`;
      this.addLog(`ERROR: Failed to start server (code: ${ret})`);
    }
    hilog.info(0x0000, 'vpnServer', 'startServer ret=%{public}d', ret);
  }

  private stop(): void {
    const ret: number = vpn_server.stopServer();
    this.status = 'stopped';
    this.isRunning = false;
    this.addLog('UDP Server stopped');
    this.stopStatsUpdate();
    hilog.info(0x0000, 'vpnServer', 'stopServer ret=%{public}d', ret);
  }

  private startTestMode(): void {
    if (this.testData.enabled) {
      this.testTimer = setInterval(() => {
        if (this.isRunning && this.testData.targetClient) {
          this.sendTestData();
        }
      }, this.testData.interval);
      this.addLog(`Test mode started - sending to ${this.testData.targetClient}`);
    } else {
      this.stopTestMode();
    }
  }

  private stopTestMode(): void {
    if (this.testTimer) {
      clearInterval(this.testTimer);
      this.testTimer = undefined;
    }
    this.addLog('Test mode stopped');
  }

  private sendTestData(): void {
    // 使用手动格式化时间，避免 toISOString() 可能的性能问题
    const now: Date = new Date();
    const timeStr: string = `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}:${String(now.getSeconds()).padStart(2, '0')}`;
    const testMessage: string = `[${timeStr}] ${this.testData.message}`;
    const ret: number = vpn_server.sendTestData(this.testData.targetClient, testMessage);
    if (ret === 0) {
      this.addLog(`Test data sent to ${this.testData.targetClient}: ${testMessage}`);
    } else {
      this.addLog(`ERROR: Failed to send test data (code: ${ret})`);
    }
  }

  private startStatsUpdate(): void {
    // 使用较长的更新间隔（2秒）减少UI更新频率，避免频繁调用原生函数导致性能问题
    this.statsTimer = setInterval(() => {
      if (this.isRunning) {
        try {
          const nativeStats: ServerStats = vpn_server.getStats();
          const newClients: ClientInfo[] = vpn_server.getClients();
          
          // 只在统计数据或客户端列表发生变化时更新UI
          const statsChanged = 
            this.stats.packetsReceived !== nativeStats.packetsReceived ||
            this.stats.packetsSent !== nativeStats.packetsSent ||
            this.stats.bytesReceived !== nativeStats.bytesReceived ||
            this.stats.bytesSent !== nativeStats.bytesSent ||
            this.stats.lastActivity !== nativeStats.lastActivity ||
            this.stats.connectedClients.length !== newClients.length;
          
          if (statsChanged) {
            this.stats = {
              packetsReceived: nativeStats.packetsReceived,
              packetsSent: nativeStats.packetsSent,
              bytesReceived: nativeStats.bytesReceived,
              bytesSent: nativeStats.bytesSent,
              lastActivity: nativeStats.lastActivity,
              connectedClients: newClients
            };
          }
          
          // 只在有新数据时更新界面
          const newDataBuffer: string[] = vpn_server.getDataBuffer();
          if (newDataBuffer.length !== this.lastDataCount) {
            this.dataBuffer = newDataBuffer;
            this.lastDataCount = newDataBuffer.length;
          }
        } catch (error) {
          this.addLog(`ERROR: Failed to get stats: ${error}`);
        }
      }
    }, 2000); // 从1秒改为2秒，减少更新频率
  }

  private stopStatsUpdate(): void {
    if (this.statsTimer) {
      clearInterval(this.statsTimer);
      this.statsTimer = undefined;
    }
  }

  aboutToDisappear(): void {
    this.stopStatsUpdate();
    this.stopTestMode();
  }

  build() {
    Column() {
      // Header
      Row() {
        Text('Proxy UDP Server').fontSize(24).fontWeight(FontWeight.Bold)
        Blank()
        Circle({ width: 12, height: 12 })
          .fill(this.isRunning ? Color.Green : Color.Red)
          .margin({ right: 8 })
        Text(this.status.toUpperCase()).fontSize(14).fontColor(this.isRunning ? Color.Green : Color.Red)
      }
      .width('100%').padding({ bottom: 20 })

      // Control Panel
      Column() {
        Text('Server Configuration').fontSize(18).fontWeight(FontWeight.Medium).margin({ bottom: 12 })
        
        Row() {
          Text('Port:').width('20%').fontSize(16)
          TextInput({ placeholder: 'Enter port (1-65535)', text: this.port })
            .onChange((v: string) => {
              this.port = v;
            })
            .width('60%')
            .enabled(!this.isRunning)
          Text('UDP').width('20%').fontSize(14).fontColor(Color.Gray).textAlign(TextAlign.End)
        }.width('100%').margin({ bottom: 16 })

        Row() {
          Button('Start Proxy Server')
            .onClick(() => {
              this.start();
            })
            .width('48%')
            .height(40)
            .enabled(!this.isRunning)
            .backgroundColor(Color.Green)

          Button('Stop Proxy Server')
            .onClick(() => {
              this.stop();
            })
            .width('48%')
            .height(40)
            .enabled(this.isRunning)
            .backgroundColor(Color.Red)
        }.width('100%').justifyContent(FlexAlign.SpaceBetween)
      }
      .width('100%')
      .padding(16)
      .backgroundColor('#f5f5f5')
      .borderRadius(8)
      .margin({ bottom: 20 })

      // Connected Clients Panel
      Column() {
        Row() {
          Text('Connected Proxy Clients').fontSize(18).fontWeight(FontWeight.Medium)
          Blank()
          Text(`(${this.stats.connectedClients.length})`).fontSize(14).fontColor(Color.Gray)
        }.width('100%').margin({ bottom: 12 })
        
        if (this.stats.connectedClients.length > 0) {
          List() {
            ForEach(this.stats.connectedClients, (client: ClientInfo, index?: number) => {
              ListItem() {
                Row() {
                  Column() {
                    Text(`${client.ip}:${client.port}`).fontSize(14).fontWeight(FontWeight.Medium)
                    Text(`Last: ${client.lastSeen}`).fontSize(12).fontColor(Color.Gray)
                  }.layoutWeight(1)
                  
                  Column() {
                    Text(`${client.packetsCount} packets`).fontSize(12).fontColor(Color.Blue)
                    Text(`${(client.totalBytes / 1024).toFixed(1)}KB`).fontSize(12).fontColor(Color.Green)
                  }.alignItems(HorizontalAlign.End)
                }
                .width('100%')
                .padding(12)
                .backgroundColor('#ffffff')
                .borderRadius(6)
                .margin({ bottom: 8 })
                .shadow({ radius: 2, color: '#00000010', offsetX: 0, offsetY: 1 })
                .onClick(() => {
                  this.testData.targetClient = `${client.ip}:${client.port}`;
                  this.addLog(`Selected test target: ${this.testData.targetClient}`);
                })
              }
            })
          }
          .width('100%')
          .height(120)
        } else {
          Text('No clients connected').fontSize(14).fontColor(Color.Gray).textAlign(TextAlign.Center).width('100%')
        }
      }
      .width('100%')
      .padding(16)
      .backgroundColor('#f5f5f5')
      .borderRadius(8)
      .margin({ bottom: 20 })

      // Data Buffer Panel
      Column() {
        Row() {
          Text('Received Data').fontSize(18).fontWeight(FontWeight.Medium)
          Blank()
          Row() {
            Button('Test')
              .onClick(() => { 
                // 测试数据缓冲区
                try {
                  const ret: number = vpn_server.testDataBuffer();
                  if (ret === 0) {
                    this.addLog('Test data added to buffer successfully');
                  } else {
                    this.addLog(`Failed to add test data (code: ${ret})`);
                  }
                } catch (error) {
                  this.addLog(`ERROR: Failed to test data buffer: ${error}`);
                }
              })
              .fontSize(12)
              .height(24)
              .backgroundColor(Color.Transparent)
              .fontColor(Color.Green)
              .margin({ right: 8 })
            Button(this.showHexView ? 'Text' : 'Hex')
              .onClick(() => { 
                this.showHexView = !this.showHexView;
              })
              .fontSize(12)
              .height(24)
              .backgroundColor(Color.Transparent)
              .fontColor(Color.Blue)
              .margin({ right: 8 })
            Button('Clear')
              .onClick(() => { 
                // 清空服务器端数据缓冲区
                try {
                  const ret: number = vpn_server.clearDataBuffer();
                  if (ret === 0) {
                    this.addLog('Data buffer cleared successfully');
                  } else {
                    this.addLog(`Failed to clear data buffer (code: ${ret})`);
                  }
                } catch (error) {
                  this.addLog(`ERROR: Failed to clear data buffer: ${error}`);
                }
                
                // 清空界面数据
                this.dataBuffer = [];
                this.lastDataCount = 0;
              })
              .fontSize(12)
              .height(24)
              .backgroundColor(Color.Transparent)
              .fontColor(Color.Red)
          }
        }.width('100%').margin({ bottom: 8 })
        
        Scroll() {
          Column() {
            if (this.dataBuffer.length > 0) {
              ForEach(this.dataBuffer, (packet: string, index?: number) => {
                DataPacketItem({ packet: packet, showHex: this.showHexView })
              })
            } else {
              Text('No data received yet...').fontSize(14).fontColor(Color.Gray).textAlign(TextAlign.Center).width('100%')
            }
          }
          .width('100%')
        }
        .width('100%')
        .height(150)
        .scrollable(ScrollDirection.Vertical)
        .scrollBar(BarState.Auto)
      }
      .width('100%')
      .padding(16)
      .backgroundColor('#f5f5f5')
      .borderRadius(8)
      .margin({ bottom: 20 })

      // Test Mode Panel
      Column() {
        Row() {
          Text('Test Mode').fontSize(18).fontWeight(FontWeight.Medium)
          Blank()
          Toggle({ type: ToggleType.Switch, isOn: this.testData.enabled })
            .onChange((isOn: boolean) => {
              this.testData.enabled = isOn;
              this.startTestMode();
            })
        }.width('100%').margin({ bottom: 12 })
        
        Column() {
          Row() {
            Text('Target Client:').width('30%').fontSize(14)
            TextInput({ placeholder: 'IP:Port', text: this.testData.targetClient })
              .onChange((v: string) => { 
                this.testData.targetClient = v;
              })
              .width('70%')
              .enabled(this.testData.enabled)
          }.width('100%').margin({ bottom: 8 })
          
          Row() {
            Text('Test Message:').width('30%').fontSize(14)
            TextInput({ placeholder: 'Message content', text: this.testData.message })
              .onChange((v: string) => { 
                this.testData.message = v;
              })
              .width('70%')
              .enabled(this.testData.enabled)
          }.width('100%').margin({ bottom: 8 })
          
          Row() {
            Text('Interval (ms):').width('30%').fontSize(14)
            TextInput({ placeholder: '1000', text: this.testData.interval.toString() })
              .onChange((v: string) => { 
                const num = Number(v);
                if (!isNaN(num) && num > 0) {
                  this.testData.interval = num;
                }
              })
              .width('70%')
              .enabled(this.testData.enabled)
              .type(InputType.Number)
          }.width('100%')
        }
        .width('100%')
        .padding(12)
        .backgroundColor(this.testData.enabled ? '#e8f5e8' : '#f0f0f0')
        .borderRadius(6)
      }
      .width('100%')
      .padding(16)
      .backgroundColor('#f5f5f5')
      .borderRadius(8)
      .margin({ bottom: 20 })

      // Statistics Panel
      Column() {
        Text('Server Statistics').fontSize(18).fontWeight(FontWeight.Medium).margin({ bottom: 12 })
        
        Grid() {
          GridItem() {
            Column() {
              Text(this.stats.packetsReceived.toString()).fontSize(20).fontWeight(FontWeight.Bold)
              Text('Packets Rx').fontSize(12).fontColor(Color.Gray)
            }
          }
          GridItem() {
            Column() {
              Text(this.stats.packetsSent.toString()).fontSize(20).fontWeight(FontWeight.Bold)
              Text('Packets Tx').fontSize(12).fontColor(Color.Gray)
            }
          }
          GridItem() {
            Column() {
              Text(`${(this.stats.bytesReceived / 1024).toFixed(1)}KB`).fontSize(20).fontWeight(FontWeight.Bold)
              Text('Bytes Rx').fontSize(12).fontColor(Color.Gray)
            }
          }
          GridItem() {
            Column() {
              Text(`${(this.stats.bytesSent / 1024).toFixed(1)}KB`).fontSize(20).fontWeight(FontWeight.Bold)
              Text('Bytes Tx').fontSize(12).fontColor(Color.Gray)
            }
          }
        }
        .columnsTemplate('1fr 1fr')
        .rowsTemplate('1fr 1fr')
        .height(80)
        .margin({ bottom: 12 })
        
        Text(`Last Activity: ${this.stats.lastActivity}`).fontSize(12).fontColor(Color.Gray)
      }
      .width('100%')
      .padding(16)
      .backgroundColor('#f5f5f5')
      .borderRadius(8)
      .margin({ bottom: 20 })

      // Log Panel
      Column() {
        Row() {
          Text('Server Logs').fontSize(18).fontWeight(FontWeight.Medium)
          Blank()
          Button('Clear')
            .onClick(() => { 
              this.logs = [];
            })
            .fontSize(12)
            .height(24)
            .backgroundColor(Color.Transparent)
            .fontColor(Color.Blue)
        }.width('100%').margin({ bottom: 8 })
        
        Text(this.logs.join('\n') || 'No logs yet...')
          .fontSize(12)
          .fontFamily('monospace')
          .width('100%')
          .height(120)
          .backgroundColor('#000000')
          .fontColor('#00ff00')
          .padding(8)
          .borderRadius(4)
          .copyOption(CopyOptions.InApp)
      }
      .width('100%')
      .padding(16)
      .backgroundColor('#f5f5f5')
      .borderRadius(8)

      Blank()
    }
    .width('100%')
    .height('100%')
    .padding(16)
    .backgroundColor('#ffffff')
  }
}

@Component
struct DataPacketItem {
  @Prop packet: string = '';
  @Prop showHex: boolean = false;

  private parsePacketData(): PacketData {
    try {
      return JSON.parse(this.packet) as PacketData;
    } catch (e) {
      return {
        timestamp: '',
        client: '',
        data: this.packet,
        hex: this.toHex(this.packet),
        type: 'unknown'
      };
    }
  }

  private toHex(str: string): string {
    let hex: string = '';
    for (let i: number = 0; i < str.length; i++) {
      hex += str.charCodeAt(i).toString(16).padStart(2, '0') + ' ';
    }
    return hex.trim();
  }

  build() {
    Column() {
      DataPacketContentView({ packet: this.packet, showHex: this.showHex })
    }
    .width('100%')
    .margin({ bottom: 8 })
    .backgroundColor('#ffffff')
    .padding(8)
    .borderRadius(6)
    .shadow({ radius: 1, color: '#00000010', offsetX: 0, offsetY: 1 })
  }
}

@Component
struct DataPacketContentView {
  @Prop packet: string = '';
  @Prop showHex: boolean = false;

  private toHex(str: string): string {
    let hex: string = '';
    for (let i: number = 0; i < str.length; i++) {
      hex += str.charCodeAt(i).toString(16).padStart(2, '0') + ' ';
    }
    return hex.trim();
  }

  private parsePacketData(): PacketData {
    try {
      return JSON.parse(this.packet) as PacketData;
    } catch (e) {
      return {
        timestamp: '',
        client: '',
        data: this.packet,
        hex: this.toHex(this.packet),
        type: 'unknown'
      };
    }
  }

  private getDataTypeColor(type: string): string {
    switch (type) {
      case 'heartbeat': return '#FF6B6B';
      case 'data': return '#4ECDC4';
      case 'test': return '#45B7D1';
      default: return '#95A5A6';
    }
  }

  private getDataTypeLabel(type: string): string {
    switch (type) {
      case 'heartbeat': return 'HEARTBEAT';
      case 'data': return 'DATA';
      case 'test': return 'TEST';
      default: return 'UNKNOWN';
    }
  }

  build() {
      Column() {
        Row() {
          Text(this.parsePacketData().timestamp).fontSize(10).fontColor(Color.Gray).width(80)
          Text(this.parsePacketData().client).fontSize(12).fontWeight(FontWeight.Medium).width(120)
          Text(this.getDataTypeLabel(this.parsePacketData().type))
            .fontSize(8)
            .fontColor(this.getDataTypeColor(this.parsePacketData().type))
            .backgroundColor(this.getDataTypeColor(this.parsePacketData().type) + '20')
            .padding({ left: 4, right: 4, top: 2, bottom: 2 })
            .borderRadius(2)
            .margin({ left: 8 })
          Blank()
        }.width('100%').margin({ bottom: 4 })
        .visibility(this.parsePacketData().timestamp && this.parsePacketData().client ? Visibility.Visible : Visibility.None)
        
        Text(this.showHex ? this.parsePacketData().hex : this.parsePacketData().data)
          .fontSize(11)
          .fontFamily('monospace')
          .width('100%')
          .backgroundColor('#f8f8f8')
          .padding(8)
          .borderRadius(4)
          .copyOption(CopyOptions.InApp)
      }
    }
}