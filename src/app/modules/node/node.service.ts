import { CPU } from './models/cpu';
import { cpus } from 'os';
import { Injectable } from '@nestjs/common';

@Injectable()
export class NodeService {
  async cpus(): Promise<CPU[]> {
    try {
      const result = cpus();
      return result;
    } catch (e) {
      return [];
    }
  }
}
