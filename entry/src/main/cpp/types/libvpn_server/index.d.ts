export const startServer: (port: number) => number;
export const stopServer: () => number;
export const getStats: () => {
  packetsReceived: number;
  packetsSent: number;
  bytesReceived: number;
  bytesSent: number;
  lastActivity: string;
};
export const getClients: () => {
  ip: string;
  port: number;
  lastSeen: string;
  packetsCount: number;
  totalBytes: number;
}[];
export const getDataBuffer: () => string[];
export const sendTestData: (targetClient: string, message: string) => number;
export const clearDataBuffer: () => number;
