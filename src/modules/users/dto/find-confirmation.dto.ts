import { IsMongoId } from 'class-validator';

export class FindConfirmationByIdDto {
  @IsMongoId()
  confirmationId: string;
}
