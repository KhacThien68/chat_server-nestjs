import { Reflector } from '@nestjs/core';
import { AuthGuard } from '@nestjs/passport';

export class RtGuard extends AuthGuard('jwt-refresh') {
  constructor(private reflector: Reflector) {
    super();
  }
}
