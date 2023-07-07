import { Field, Int, ObjectType } from '@nestjs/graphql';
import { User } from '../entities/user.entity';

@ObjectType()
export class ResponseUserDto {
  @Field(() => [User], { nullable: true })
  items: User[];

  @Field(() => Int, { nullable: true })
  totalCount: number;

  @Field(() => Int, { nullable: true })
  currentPage: number;

  @Field(() => Int, { nullable: true })
  totalPages: number;

  @Field(() => Boolean, { nullable: true })
  hasNextPage: boolean;
}
