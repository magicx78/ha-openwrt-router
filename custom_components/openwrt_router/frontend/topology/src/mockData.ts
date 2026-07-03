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
    // v1.21 port-device model — exercises every badge/tooltip/popup branch
    portStats: [
      {
        name: 'wan', up: true, speed_mbps: 1000, duplex: 'full',
        role: 'wan', connectedDevices: [], deviceCount: 0,
        mappingConfidence: 'none',
      },
      {
        // single device, full identity → high confidence + name badge
        name: 'lan1', up: true, speed_mbps: 100, duplex: 'full', vlanIds: [10],
        role: 'lan',
        connectedDevices: [
          { mac: 'de:ad:be:ef:00:01', ip: '10.10.10.23', name: 'reolink-cam', source: 'fdb+dhcp+arp', confidence: 'high', webUrl: 'http://10.10.10.23' },
        ],
        primaryDevice: { mac: 'de:ad:be:ef:00:01', ip: '10.10.10.23', name: 'reolink-cam', source: 'fdb+dhcp+arp', confidence: 'high', webUrl: 'http://10.10.10.23' },
        deviceCount: 1, hasDownstreamSwitch: false,
        webUrl: 'http://10.10.10.23', mappingConfidence: 'high',
      },
      {
        // AP + extra device behind an unmanaged switch → "Switch/AP" badge
        name: 'lan2', up: true, speed_mbps: 1000, duplex: 'full', vlanIds: [10, 20],
        role: 'lan', connectedDevice: 'aPclient1',
        connectedDevices: [
          { mac: 'de:ad:be:ef:00:02', ip: '10.10.10.2', name: 'aPclient1', source: 'trunk_map', confidence: 'high', webUrl: 'http://10.10.10.2', isRouter: true, routerNodeId: 'ap1' },
          { mac: 'de:ad:be:ef:00:03', ip: '10.10.10.40', name: undefined, source: 'fdb+arp', confidence: 'medium', webUrl: 'http://10.10.10.40' },
          { mac: 'de:ad:be:ef:00:04', ip: undefined, name: undefined, source: 'fdb', confidence: 'medium' },
        ],
        primaryDevice: { mac: 'de:ad:be:ef:00:02', ip: '10.10.10.2', name: 'aPclient1', source: 'trunk_map', confidence: 'high', webUrl: 'http://10.10.10.2', isRouter: true, routerNodeId: 'ap1' },
        deviceCount: 3, hasDownstreamSwitch: true,
        webUrl: 'http://10.10.10.2', mappingConfidence: 'high',
      },
      {
        // link up, no FDB entries → "Unbekannt"
        name: 'lan3', up: true, speed_mbps: 1000, duplex: 'full',
        role: 'lan', connectedDevices: [], deviceCount: 0,
        mappingConfidence: 'none',
      },
    ],
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
      // LEGACY fixture on purpose: port_stats WITHOUT the v1.21 fields —
      // proves old snapshots render exactly like before (no badges/dots).
      portStats: [
        { name: 'wan', up: true, speed_mbps: 1000, duplex: 'full' },
        { name: 'lan1', up: true, speed_mbps: 100, duplex: 'full', connectedDevice: 'printer-og' },
        { name: 'lan2', up: false, speed_mbps: null },
      ],
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
