import { Injectable, UnauthorizedException } from '@nestjs/common';
import { UsersRepository } from './users.repository';
import { InjectRepository } from '@nestjs/typeorm';
import { AuthCredentialsDto } from './dto/auth-credentials.dto';
import * as bycrpt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './dto/jwt-payload.nterface';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(UsersRepository)
    private usersRepository: UsersRepository,
    private jwtService: JwtService,
  ) {}

  async signUp(authCredentiaslDto: AuthCredentialsDto): Promise<void> {
    return this.usersRepository.createUser(authCredentiaslDto);
  }

  async signIn(
    authCredentialsDto: AuthCredentialsDto,
  ): Promise<{ acessToken: string }> {
    const { username, password } = authCredentialsDto;
    const user = await this.usersRepository.findOne({ username });

    if (user && (await bycrpt.compare(password, user.password))) {
      const payload: JwtPayload = { username };
      const acessToken: string = await this.jwtService.sign(payload);
      return { acessToken };
    } else {
      throw new UnauthorizedException('Please check you password');
    }
  }
}
