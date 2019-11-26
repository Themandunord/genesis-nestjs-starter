import { Injectable } from '@nestjs/common';
import { UserInputError } from 'apollo-server';

@Injectable()
export class AppService {
  public hasValidationErrors(validationErrors: object) {
    return Object.keys(validationErrors).length > 0;
  }

  public throwValidationErrors(action: string, validationErrors: object) {
    throw new UserInputError(`Failed to ${action} due to validation errors`, {
      validationErrors,
    });
  }
}
