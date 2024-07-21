import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto/auth.dto';
import { Tokens } from './types/types';
import { AccessGurad } from './guards/ac.guard';
import { RefreshGuard } from './guards/rt.guard';
import { GetCurrentUser } from './decorators/get-current-user';
import { GetCurrentUserId } from './decorators/get-current-userId';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @HttpCode(HttpStatus.CREATED)
  @Post('/local/signup')
  signUp(@Body() dto: AuthDto): Promise<Tokens> {
    return this.authService.signUp(dto);
  }
  @HttpCode(HttpStatus.OK)
  @Post('/local/signin')
  signIn(@Body() dto: AuthDto): Promise<Tokens> {
    return this.authService.signIn(dto);
  }
  @UseGuards(AccessGurad)
  @Post('signout')
  @HttpCode(HttpStatus.OK)
  signOut(@GetCurrentUser('userId') userId: number) {
    return this.authService.signOut(userId);
  }
  @UseGuards(RefreshGuard)
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  async refreshToken(
    @GetCurrentUser('refresh') refresh: string,
    @GetCurrentUserId() userId: number,
  ) {
    return await this.authService.refreshToken(userId, refresh);
  }
}
