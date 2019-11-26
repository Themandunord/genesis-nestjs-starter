import { createParamDecorator } from '@nestjs/common';

export const Session = createParamDecorator(
  (data, [root, args, { req }]) => req.session,
);
