import { IsString, MinLength } from 'class-validator';

export class RecoveryPasswordDto {
  @IsString()
  @MinLength(8)
  password: string;
}
