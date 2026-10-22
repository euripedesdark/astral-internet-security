import Firewall from '../modules/firewall/pages/Index';

export const ORDER = ['firewall'];
export const ICONS: Record<string, string> = {
  firewall: 'pi pi-shield'
};
export const PAGES: Record<string, any> = {
  firewall: Firewall
};
