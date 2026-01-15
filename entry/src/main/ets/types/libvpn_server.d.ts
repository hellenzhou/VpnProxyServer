/**
 * VPN Server Native Module Type Definitions
 */

export interface VpnServerModule {
  /**
   * Start the VPN server on the specified port
   * @param port - The port number to listen on (1-65535)
   * @returns 0 on success, negative value on error
   */
  startServer(port: number): number;

  /**
   * Stop the VPN server
   * @returns 0 on success, negative value on error
   */
  stopServer(): number;

  /**
   * Get current server statistics
   * @returns Server statistics object
   */
  getStats(): ServerStats;

  /**
   * Get list of connected clients
   * @returns Array of client information
   */
  getClients(): ClientInfo[];

  /**
   * Get data buffer containing received packets
   * @returns Array of packet data strings
   */
  getDataBuffer(): string[];

  /**
   * Test data buffer functionality
   * @returns 0 on success, negative value on error
   */
  testDataBuffer(): number;

  /**
   * Send test data to a specific client
   * @param targetClient - Client address in format "IP:PORT"
   * @param message - Test message to send
   * @returns 0 on success, negative value on error
   */
  sendTestData(targetClient: string, message: string): number;

  /**
   * Clear the data buffer
   * @returns 0 on success, negative value on error
   */
  clearDataBuffer(): number;

  /**
   * Test DNS query functionality
   * @returns Test result string
   */
  testDNSQuery(): string;
}

export interface ServerStats {
  packetsReceived: number;
  packetsSent: number;
  bytesReceived: number;
  bytesSent: number;
  lastActivity: string;
  connectedClients: ClientInfo[];
}

export interface ClientInfo {
  ip: string;
  port: number;
  lastSeen: string;
  packetsCount: number;
  totalBytes: number;
}

declare const vpnServer: VpnServerModule;
export default vpnServer;
