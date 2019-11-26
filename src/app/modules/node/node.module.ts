import { Module } from '@nestjs/common';
import { NodeResolvers } from './node.resolvers';
import { NodeService } from './node.service';

@Module({
  providers: [NodeResolvers, NodeService],
  exports: [NodeService],
})
export class NodeModule {}
