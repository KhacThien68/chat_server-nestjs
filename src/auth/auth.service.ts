import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { SigninDto, SignupDto } from './dto';

@Injectable()
export class AuthService {
  constructor(private prismaService: PrismaService) {}
  signup(dto: SignupDto) {
    return { dto: dto };
  }

  signin(dto: SigninDto) {
    return { msg: 'signin' };
  }
}
