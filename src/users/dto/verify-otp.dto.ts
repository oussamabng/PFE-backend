import { Field, InputType, ObjectType } from '@nestjs/graphql';
import { IsNotEmpty, IsString } from 'class-validator';

@InputType()
export class VerifyOtp {
  @IsNotEmpty()
  @IsString()
  @Field(() => String)
  code: string;

  @IsString()
  @Field(() => String)
  email: string;
}
