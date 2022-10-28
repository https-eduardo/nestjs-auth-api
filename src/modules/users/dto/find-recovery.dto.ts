import { IsMongoId } from 'class-validator';

export class FindRecoveryByIdDto {
  @IsMongoId()
  recoveryId: string;
}
