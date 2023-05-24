import { ForbiddenException, HttpStatus, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { SigninDto, SignupDto } from './dto';
import { ConfigService } from '@nestjs/config';
import * as argon from 'argon2';
import { Prisma } from '@prisma/client';
import { JwtService } from '@nestjs/jwt';
import { Token } from './entities';
import { AuthResponse } from './response/auth.response';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private config: ConfigService,
    private jwt: JwtService,
  ) {}

  async signup(dto: SignupDto): Promise<AuthResponse> {
    // save the password
    const hash = await argon.hash(dto.password);

    // save the new user to the database
    try {
      const user = await this.prisma.user.create({
        data: {
          hash: hash,
          email: dto.email,
        },
      });

      // return token
      const token = await this.signToken(user.id, user.email);
      await this.updateRtHash(user.id, token.refreshToken);
      return {
        token: token,
        status: HttpStatus.CREATED,
        user: user,
      };
    } catch (err) {
      if (err instanceof Prisma.PrismaClientKnownRequestError) {
        if (err.code === 'P2002') {
          throw new ForbiddenException('this email should be unique');
        }
      }
      throw err;
    }
  }

  async signin(dto: SigninDto): Promise<AuthResponse> {
    // find the user by email
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });
    // if the user doesnt exist, throw exception
    if (!user) {
      throw new ForbiddenException('User does not exist');
    }
    // compare the password
    const pwMatches = await argon.verify(user.hash, dto.password);
    // if the passwword incorrect, throw exception
    if (!pwMatches) {
      throw new ForbiddenException('Email or Password is incorrect');
    }

    const token = await this.signToken(user.id, user.email);
    console.log(token);
    await this.updateRtHash(user.id, token.refreshToken);
    delete user.hash;
    delete user.hashRt;
    delete user.createdAt;
    delete user.updatedAt;
    return {
      token: token,
      status: HttpStatus.OK,
      user: user,
    };
  }

  async logout(userId) {
    await this.prisma.user.updateMany({
      where: {
        id: userId,
        hashRt: {
          not: null,
        },
      },
      data: {
        hashRt: null,
      },
    });
  }

  async refreshToken(userId: number, rt: string) {
    const user = await this.prisma.user.findUnique({
      where: {
        id: userId,
      },
    });
    if (!user) throw new ForbiddenException('Access denied');

    const rtMatches = await argon.verify(user.hashRt, rt);
    if (!rtMatches) throw new ForbiddenException('Access denied');

    const token = await this.signToken(user.id, user.email);
    await this.updateRtHash(user.id, token.refreshToken);
    return token;
  }
  async signToken(userId: number, email: string): Promise<Token> {
    const payload = {
      sub: userId,
      email: email,
    };
    const [at, rt] = await Promise.all([
      this.jwt.signAsync(payload, {
        expiresIn: this.config.get('JWT_ACCESS_EXPIRED'),
        secret: this.config.get('AT_JWT_SECRET'),
      }),
      this.jwt.signAsync(payload, {
        expiresIn: this.config.get('JWT_REFRESH_EXPIRED'),
        secret: this.config.get('RT_JWT_SECRET'),
      }),
    ]);
    return {
      accessToken: at,
      refreshToken: rt,
    };
  }

  async updateRtHash(userId: number, rt: string) {
    const hash = await argon.hash(rt);
    await this.prisma.user.update({
      where: {
        id: userId,
      },
      data: {
        hashRt: hash,
      },
    });
  }
}
