import { Field, ObjectType } from '@nestjs/graphql';
import { UserStatus } from '../enums/user-status.dto';

@ObjectType()
export class DeliveryResponseDto {
  @Field(() => String, { nullable: true })
  access_token: string;

  @Field(() => String, { nullable: true })
  refresh_token: string;

  @Field(() => String)
  status: string;
}
