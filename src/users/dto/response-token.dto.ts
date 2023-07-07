import { InputType, Field, ObjectType } from '@nestjs/graphql';
import { IsNotEmpty, IsString } from 'class-validator';

@ObjectType()
export class ResponseTokenDto {
  @IsNotEmpty()
  @IsString()
  @Field(() => String)
  access_token: string;

  @IsNotEmpty()
  @IsString()
  @Field(() => String)
  refresh_token: string;
}
