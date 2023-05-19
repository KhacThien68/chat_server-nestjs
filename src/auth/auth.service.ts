import {
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { SigninDto, SignupDto } from './dto';
import { ConfigService } from '@nestjs/config';
import * as argon from 'argon2';
import { Prisma, User } from '@prisma/client';
import { JwtService } from '@nestjs/jwt';
import { Token } from './entities';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private config: ConfigService,
    private jwt: JwtService,
  ) {}

  async signup(dto: SignupDto) {
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
      const token = this.signToken(user.id, user.email);
      await this.updateRtHash(user.id, (await token).refreshToken);
      return token;
    } catch (err) {
      if (err instanceof Prisma.PrismaClientKnownRequestError) {
        if (err.code === 'P2002') {
          throw new ForbiddenException('this email should be unique');
        }
      }
      throw err;
    }
  }

  async signin(dto: SigninDto): Promise<Token> {
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
      throw new ForbiddenException('Password is incorrect');
    }

    const token = this.signToken(user.id, user.email);
    await this.updateRtHash(user.id, (await token).refreshToken);
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

  verifyToken = async (token: string) => {
    try {
      const payload = this.jwt.verify(token);
      const { userId } = payload;

      const user = await this.prisma.user.findUnique({ where: { id: userId } });
      if (!user) {
        throw new UnauthorizedException('Token is invalid');
      }

      return payload;
    } catch (e) {
      throw new UnauthorizedException('Token is invalid');
    }
  };
}
