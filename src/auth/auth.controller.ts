import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto/auth.dto';
import { Tokens } from './types/types';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('/local/signup')
  signUp(@Body() dto: AuthDto): Promise<Tokens> {
    return this.authService.signUp(dto);
  }
  @Post('/local/signin')
  signIn(@Body() dto: AuthDto) {
    this.authService.signIn(dto);
  }
  @Post('/local/signout')
  signOut() {
    this.authService.signOut();
  }
  @Post('refresh')
  refreshToken() {
    this.authService.refreshToken();
  }
}
