import {
  Body,
  Controller,
  Get,
  Post,
  UseGuards,
  Req,
  Patch,
  Res,
  HttpCode,
  Param,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { JwtAuthGuard } from 'src/modules/auth/guards/jwt-auth.guard';
import { UsersService } from './users.service';
import { ChangePasswordDto } from './dto/change-password.dto';
import { CreateUserDto } from './dto/create-user.dto';
import { RequestRecoveryDto } from './dto/request-recovery.dto';
import { FindRecoveryByIdDto } from './dto/find-recovery.dto';
import { RecoveryPasswordDto } from './dto/recovery-password.dto';
import { FindConfirmationByIdDto } from './dto/find-confirmation.dto';
import { TokenType } from '@prisma/client';
import { User } from '../../common/decorators/user.decorator';
import { JwtUserPayload } from '../../common/types/user-payload.type';

@Controller('users')
export class UsersController {
  constructor(private readonly service: UsersService) {}
  @Post()
  create(@Body() createUserDto: CreateUserDto) {
    return this.service.create(createUserDto);
  }

  @Patch('change-password')
  @UseGuards(JwtAuthGuard)
  @HttpCode(200)
  async changePassword(
    @User() user: JwtUserPayload,
    @Res({ passthrough: true }) res: Response,
    @Body() changePasswordDto: ChangePasswordDto,
  ) {
    await this.service.changePassword(user.userId, changePasswordDto);
    res.cookie('access_token', null);
    res.cookie('refresh_token', null);
  }

  @Post('request-recovery')
  @HttpCode(200)
  async requestRecovery(@Body() requestRecoveryDto: RequestRecoveryDto) {
    return await this.service.requestRecovery(requestRecoveryDto.email);
  }

  @Patch('confirm/:confirmationId')
  async confirm(@Param() findConfirmationByIdDto: FindConfirmationByIdDto) {
    return await this.service.confirm(findConfirmationByIdDto.confirmationId);
  }

  @Get('recovery/:recoveryId')
  async findRecoveryToken(@Param() findRecoveryByIdDto: FindRecoveryByIdDto) {
    return await this.service.findTokenById(
      findRecoveryByIdDto.recoveryId,
      TokenType.RECOVERY,
    );
  }

  @Patch('recovery/:recoveryId')
  async recovery(
    @Param() findRecoveryByIdDto: FindRecoveryByIdDto,
    @Body() recoveryPasswordDto: RecoveryPasswordDto,
  ) {
    return await this.service.recoveryPassword(
      findRecoveryByIdDto.recoveryId,
      recoveryPasswordDto,
    );
  }

  @Get('me')
  @UseGuards(JwtAuthGuard)
  me(@User() user: JwtUserPayload) {
    return user;
  }
}
