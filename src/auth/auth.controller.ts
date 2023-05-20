import {
  Body,
  Controller,
  Post,
  HttpCode,
  HttpStatus,
  UseGuards,
  Req,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { SigninDto, SignupDto } from './dto';
import { Token } from './entities';
import { AuthGuard } from '@nestjs/passport';
import { Request } from 'express';
import { GetUser } from './decorator';
import { User } from '@prisma/client';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('signup')
  @HttpCode(HttpStatus.CREATED)
  signup(@Body() dto: SignupDto): Promise<Token> {
    return this.authService.signup(dto);
  }

  @Post('signin')
  @HttpCode(HttpStatus.OK)
  signin(@Body() dto: SigninDto): Promise<Token> {
    return this.authService.signin(dto);
  }

  @UseGuards(AuthGuard('jwt'))
  @Post('logout')
  @HttpCode(HttpStatus.OK)
  logout(@GetUser() user: User) {
    return this.authService.logout(user['id']);
  }

  @UseGuards(AuthGuard('jwt-refresh'))
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  refreshToken(@Req() req: Request) {}
}
