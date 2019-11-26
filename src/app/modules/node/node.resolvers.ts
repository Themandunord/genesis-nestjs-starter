import { NodeService } from './node.service';
import { Resolver, Query } from '@nestjs/graphql';
import { CPU } from './models/cpu';

@Resolver('Node')
export class NodeResolvers {
  constructor(private readonly nodeService: NodeService) {}

  @Query(returns => [CPU])
  async cpus(): Promise<CPU[]> {
    const result = await this.nodeService.cpus();
    return result;
  }
}
