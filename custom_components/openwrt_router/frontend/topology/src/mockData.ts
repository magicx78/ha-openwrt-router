import { TopologyData } from './types';

export const MOCK_DATA: TopologyData = {
  timestamp: new Date().toISOString(),
  gateway: {
    id: 'gw',
    name: 'sECUREaP-gATEWAy',
    model: 'Cudy WR3000',
    ip: '10.10.10.1',
    wanIp: '93.184.216.34',
    uptime: '12d 4h 32m',
    status: 'online',
  },
  accessPoints: [
    {
      id: 'ap1',
      name: 'aPclient1',
      model: 'Cudy WR3000',
      ip: '10.10.10.2',
      uplinkType: 'wired',
      uplinkTo: 'gw',
      clientCount: 4,
      backhaulSignal: -45,
      status: 'online',
    },
    {
      id: 'ap2',
      name: 'aP-Mesh',
      model: 'Cudy WR3000',
      ip: '10.10.10.3',
      uplinkType: 'mesh',
      uplinkTo: 'ap1',
      clientCount: 3,
      backhaulSignal: -68,
      status: 'warning',
    },
    {
      id: 'ap3',
      name: 'aP4',
      model: 'Cudy WR3000',
      ip: '10.10.10.4',
      uplinkType: 'wired',
      uplinkTo: 'gw',
      clientCount: 6,
      backhaulSignal: -42,
      status: 'online',
    },
  ],
  clients: [
    // ap1
    { id: 'c1', name: "Sarah's iPhone", hostname: 'iphone-sarah', ip: '10.10.10.101', mac: 'AA:BB:CC:01', apId: 'ap1', category: 'smartphone', signal: -55, band: '5 GHz', status: 'online', manufacturer: 'Apple' },
    { id: 'c2', name: "Tom's MacBook", hostname: 'macbook-tom', ip: '10.10.10.102', mac: 'AA:BB:CC:02', apId: 'ap1', category: 'laptop', signal: -48, band: '5 GHz', status: 'online', manufacturer: 'Apple' },
    { id: 'c3', name: 'Smart TV', hostname: 'samsung-tv', ip: '10.10.10.103', mac: 'AA:BB:CC:03', apId: 'ap1', category: 'iot', signal: -62, band: '2.4 GHz', status: 'online', manufacturer: 'Samsung' },
    { id: 'c4', name: 'Nest Thermostat', hostname: 'nest-therm', ip: '10.10.10.104', mac: 'AA:BB:CC:04', apId: 'ap1', category: 'iot', signal: -71, band: '2.4 GHz', status: 'warning', manufacturer: 'Google' },
    // ap2 (mesh AP — one client offline)
    { id: 'c5', name: "Max's Android", hostname: 'pixel-max', ip: '10.10.10.105', mac: 'AA:BB:CC:05', apId: 'ap2', category: 'smartphone', signal: -58, band: '5 GHz', status: 'online', manufacturer: 'Google' },
    { id: 'c6', name: 'Work Laptop', hostname: 'thinkpad', ip: '10.10.10.106', mac: 'AA:BB:CC:06', apId: 'ap2', category: 'laptop', signal: -65, band: '5 GHz', status: 'online', manufacturer: 'Lenovo' },
    { id: 'c7', name: 'Hue Bridge', hostname: 'hue-bridge', ip: '10.10.10.107', mac: 'AA:BB:CC:07', apId: 'ap2', category: 'iot', signal: -73, band: '2.4 GHz', status: 'offline', manufacturer: 'Philips' },
    // ap3
    { id: 'c8', name: 'Guest Phone', hostname: 'guest-1', ip: '10.10.20.10', mac: 'AA:BB:CC:08', apId: 'ap3', category: 'guest', signal: -61, band: '2.4 GHz', status: 'online' },
    { id: 'c9', name: 'Ring Doorbell', hostname: 'ring-door', ip: '10.10.10.109', mac: 'AA:BB:CC:09', apId: 'ap3', category: 'iot', signal: -54, band: '2.4 GHz', status: 'online', manufacturer: 'Ring' },
    { id: 'c10', name: "Lisa's iPad", hostname: 'ipad-lisa', ip: '10.10.10.110', mac: 'AA:BB:CC:0A', apId: 'ap3', category: 'smartphone', signal: -49, band: '5 GHz', status: 'online', manufacturer: 'Apple' },
    { id: 'c11', name: 'Chromecast 4K', hostname: 'chromecast', ip: '10.10.10.111', mac: 'AA:BB:CC:0B', apId: 'ap3', category: 'iot', signal: -67, band: '5 GHz', status: 'online', manufacturer: 'Google' },
    { id: 'c12', name: 'Synology NAS', hostname: 'synology', ip: '10.10.10.112', mac: 'AA:BB:CC:0C', apId: 'ap3', category: 'other', signal: -44, band: '5 GHz', status: 'online', manufacturer: 'Synology' },
    { id: 'c13', name: "Alex's MacBook", hostname: 'mbp-alex', ip: '10.10.10.113', mac: 'AA:BB:CC:0D', apId: 'ap3', category: 'laptop', signal: -52, band: '5 GHz', status: 'online', manufacturer: 'Apple' },
  ],
  switchNodes: [],
};
